# WireGuard in `leas-native` — sans-I/O codec + smoltcp device

Date: 2026-11-26
Status: **implemented 2026-11-26** — plan `../plans/2026-11-26-wireguard-native.md`; ADR 0019.
Origin: user request "implement wireguard protocol in leas-native; sans-I/O if possible; grill the details".
Evidence: `thirdparty/wireguard-go` (`master@b3bc704ef0ee`) — `device/{noise-protocol,cookie,timers,constants,replay}.go`, read in full; `thirdparty/ferrox` (`v0.4.3`) — `crates/ferrox-core/src/wireguard/{kdf,handshake,transport,device}.rs` and `ferrox-app/src/{wg,wg_stack}.rs`; `thirdparty/ZeroNet` (`v0.3.6`) — `crates/zero-protocol/src/wg_stack.rs`, `crates/zero-tun/src/lib.rs`, `vendor/netstack-smoltcp/PATCHES.md`; `thirdparty/shoes` (`v0.3.7`) — `README.md` §smoltcp, `DEPENDENCIES.md` §smoltcp; workspace: `crates/leas-proto/src/proto_spec/wireguard.rs`, `crates/leas-native/src/{shape,capability,protocol/mod,inbound/outbound}.rs`, `crates/leas-dns/src/{lib,dnscrypt}.rs`.

Grilled 2026-11-26. Answers: **B** (full parity: WG becomes a usable outbound) · **own codec** (no boringtun in prod) · **tunnel DNS via `leas-dns`, local fallback only when no configured resolver is alive** · **extend `leas-dns`** with a plain-IP arm · acceptance bar **A** (TCP + UDP ASSOCIATE + tunneled DNS + WARP `reserved`, IPv4 and IPv6, badge flips).

---

## 1. Why this exists

`crates/leas-native/src/protocol/wireguard/mod.rs` is a two-line placeholder and `protocol::connect` maps `ProtocolConfig::Wireguard(_)` to `not_impl`. `capability::support_reason` refuses the kind, `shape::connect_shape` classifies it `DeviceTunnel`, and `capability::tests::non_native_kinds_unsupported` pins the refusal. Stored WireGuard rows therefore resolve to the sing-box subprocess, and in a native-only session they render `[n-a]`.

WireGuard is layer 3. The engine's uniform contract is `connect(&LinkContext, BoxStream) -> BoxStream`; a WireGuard outbound has no stream to hand it. Serving SOCKS from a WireGuard tunnel requires a TCP/IP state machine in user space — which is why all three Go cores wrap `wireguard-go`'s device in gVisor's netstack (`Xray-core/proxy/wireguard`, `sing-box/protocol/wireguard/endpoint.go` → `transport/wireguard`, `mihomo/adapter/outbound/wireguard.go` `ipStackGVisor`). This spec takes the Rust equivalent: `smoltcp`.

## 2. Wire contract

`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`. `H0 = BLAKE2s256(C)`, then `H = mixHash(H0, "WireGuard v1 zx2c4 Jason@zx2c4.com")`; `chainKey0 = BLAKE2s256(C)`. All hashes are BLAKE2s; `mixHash(x) = BLAKE2s256(H ‖ x)`; `mixKey(x) = (CK, _) = KDF2(CK, x)`. `KDF1/2/3` are RFC 2104 HMAC-BLAKE2s with the chaining key as key, emitting 32/64/96 bytes (the reference's `device/noise-protocol.go` + `kdf.go`; `ferrox-core/src/wireguard/mod.rs` states the same).

### 2.1 Messages

Every message starts with a 4-byte little-endian type word whose **low byte is the type**; bytes 1..4 are the WARP `reserved` field (§2.4).

| Type | Size | Layout (offsets) |
| --- | --- | --- |
| 1 initiation | 148 | `type` 0..4, `sender` 4..8, `ephemeral` 8..40, `static` 40..88 (32 + 16 tag), `timestamp` 88..116 (12 + 16 tag), `mac1` 116..132, `mac2` 132..148 |
| 2 response | 92 | `type` 0..4, `sender` 4..8, `receiver` 8..12, `ephemeral` 12..44, `empty` 44..60 (16 tag), `mac1` 60..76, `mac2` 76..92 |
| 3 cookie reply | 64 | `type` 0..4, `receiver` 4..8, `nonce` 8..32 (24), `cookie` 32..64 (16 + 16 tag) |
| 4 transport | 16 + n + 16 | `type` 0..4, `receiver` 4..8, `counter` 8..16 (u64 LE), content, Poly1305 tag |

A transport packet with no content is a keepalive (32 bytes). Content is padded to a multiple of 16 before sealing (`PaddingMultiple = 16`); the receiver strips padding after decryption by parsing the inner IP header length. **The padding is not capped by the interface MTU**: the MTU bounds the inner IP packet, and the record that carries it grows by the 16-byte header, the 16-byte tag and the padding, so a 1420-byte packet becomes a ~1456-byte datagram (the reference's `MaxContentSize` is 65503, not `MTU − 32` — capping there refuses every full segment; found by the T9 loss row).

### 2.2 Handshake

Initiator (`CreateMessageInitiation`):

1. `H = mixHash(InitialHash, S_pub_peer)`; fresh ephemeral `e`;
2. `H = mixHash(H, E_pub)`; `CK = KDF1(CK, E_pub)`;
3. `(CK, k) = KDF2(CK, DH(e, S_pub_peer))`; seal `S_pub_local` with `k`, nonce 0, AAD `H`; `H = mixHash(H, static_ciphertext)`;
4. `(CK, k) = KDF2(CK, DH(s, S_pub_peer))` (precomputed static-static); seal `TAI64N(now)` (12 bytes) with `k`, nonce 0, AAD `H`; `H = mixHash(H, timestamp_ciphertext)`;
5. `sender` = a local 32-bit index (fresh per handshake).

Responder (`CreateMessageResponse`), consuming the initiation first:

1. `H = mixHash(H, E_pub_resp)`; `CK = KDF1(CK, E_pub_resp)`;
2. `CK = KDF1(CK, DH(e_resp, e_init))`; `CK = KDF1(CK, DH(e_resp, s_init))`;
3. `(CK, τ, k) = KDF3(CK, psk)`; `H = mixHash(H, τ)`; seal empty with `k`, nonce 0, AAD `H`; `H = mixHash(H, empty_ciphertext)`.

Session (`BeginSymmetricSession`): `(send, recv) = KDF2(CK, nil)`; the initiator takes `send` first, the responder `recv` first. Both directions are ChaCha20-Poly1305 with a 12-byte nonce = `00 00 00 00 ‖ counter(u64 LE)`.

Initiation replay/flood protection is responder-side only (TAI64N monotonic + one-per-50 ms); a client never needs it.

### 2.3 MACs and cookies

- `mac1_key = BLAKE2s256("mac1----" ‖ S_pub_peer)`; `mac1 = BLAKE2s128_keyed(mac1_key, msg[..len-32])`.
- `cookie_enc_key = BLAKE2s256("cookie--" ‖ S_pub_peer)`; `cookie = BLAKE2s128_keyed(secret, src_address)`; `mac2 = BLAKE2s128_keyed(cookie, msg[..len-16])`.
- A cookie reply is XChaCha20-Poly1305 under `cookie_enc_key`, 24-byte nonce, AAD = the refused message's `mac1`; it carries the 16-byte cookie plus tag.
- **Client obligations**: verify `mac1` on every handshake message received; store a received cookie and set `mac2` on the next initiation/response; refresh a stored cookie after 120 s (`CookieRefreshTime`). The `src_address` marshalling only matters to a responder, so a client never computes a cookie.

### 2.4 Reserved bytes (WARP)

`reserved` is a 3-byte value carried in bytes 1..4 of the type word. Rule (from `ferrox-core/src/wireguard/transport.rs:62-130`, `device.rs:265,338,806`): build the message with those bytes **zero**, compute `mac1`/`mac2` over the zeroed bytes, then stamp `reserved`; on receive, copy the 3 bytes off, zero them, verify, parse, and keep the copied value only for logging. Applies to all four message types. Without `reserved` the bytes stay zero, which is the reference behaviour.

### 2.5 Timers and counters

| Constant | Value | Use |
| --- | --- | --- |
| `RekeyAfterTime` | 120 s | initiate a new handshake while the old key still sends |
| `RejectAfterTime` | 180 s | stop sending, stop accepting the old session |
| `RekeyAfterMessages` | `1<<60` | message-count rekey trigger |
| `RejectAfterMessages` | `(1<<64)-(1<<13)-1` | counter ceiling; at or past it the record is refused |
| `RekeyAttemptTime` | 90 s | give up on the current handshake attempt |
| `RekeyTimeout` | 5 s | retransmit the initiation (≤ 18 attempts) |
| `RekeyTimeoutJitterMaxMs` | 334 | jitter added to the retransmit timer |
| `KeepaliveTimeout` | 10 s | send a keepalive after receiving data, if nothing was sent since |
| `CookieRefreshTime` | 120 s | cookie lifetime |
| `PaddingMultiple` | 16 | transport payload padding |
| replay window | 8128 | RFC 6479 ring, 127 blocks × 64 bits |

A pending payload is staged while no session exists and flushed on the first sealed packet (keepalives never flush the queue as data). Persistent keepalive, when configured, refreshes a 10 s timer whether or not traffic flows.

## 3. Design

### 3.1 Module map

```text
crates/leas-native/src/protocol/wireguard/
  mod.rs          device params from WireguardConfig (keys, addrs, mtu, reserved, dns)
  keys.rs         base64/hex key decode, clamp, zeroize, static-static precompute
  core/           SANS-I/O: no tokio, no sockets, no clock reads
    kdf.rs        KDF1/2/3 over BLAKE2s (blake2 0.11, keyed + HMAC)
    handshake.rs  initiation/response/cookie encode+decode, transcript state
    transport.rs  seal/open, reserved stamping, replay window, cookie MACs
    device.rs     Tunnel: initiate/send/receive/poll(now) -> Vec<Event>, timers, session rotation
  stack/          the only place that touches a runtime or a socket
    net.rs        smoltcp Device (Medium::Ip) + Interface + SocketSet driver task
    flow.rs       TcpFlow (AsyncRead+AsyncWrite over bounded rings), UdpFlow
    dns.rs        hickory ConnectionProvider over netstack sockets
  pool.rs         WgPool: one device per profile identity, idle shutdown
```

`core/` takes `now: u64` (Unix seconds) and returns events; it never reads a clock and never allocates per packet beyond the `Event` vector it is handed. `device.rs` mirrors `ferrox-core/src/wireguard/device.rs`'s boundary (`initiate/send/receive/poll`) — the shape is ported, not the code.

### 3.2 Dependencies

- `smoltcp = "0.14.0"`, `default-features = false`, features `std`, `medium-ip`, `proto-ipv4`, `proto-ipv6`, `socket-tcp`, `socket-udp`, `iface-max-addr-count-2` (all present in 0.14.0's manifest; `socket-tcp-cubic` exists too and is a follow-up knob, not needed for the first slice). 0.14.0 is the project's latest-major/minor convention and the version `ferrox-app` and `shadowsocks-rust` run; `ZeroNet`'s 0.12 pin is a reference choice, not a constraint.
- No `boringtun`/`gotatun`: their tree pulls `aead 0.5.0-pre`, `chacha20poly1305 0.10.0-pre`, `blake2 0.10` against our 0.11 line, and `Tunn` reads `Instant::now()` itself. Test-only fallback allowed if the sing-box oracle cannot serve (§5.2).
- No new crypto: `chacha20poly1305 0.11` (ChaCha20-Poly1305 for records, XChaCha20-Poly1305 for cookie replies), `blake2 0.11` (BLAKE2s-256/128, keyed), `x25519-dalek` for DH — all present with `zeroize`.
- `#![forbid(unsafe_code)]` survives: `smoltcp 0.14.0` is `#![deny(unsafe_code)]` (`src/lib.rs:2`); its `unsafe` lives only in `phy/sys/*` behind `phy-sys` features we do not enable.

### 3.3 Device parameters

| Field | Rule |
| --- | --- |
| `private_key` | base64 (share link) or hex (xray JSON dialect); decode to 32 bytes, clamp, zeroize on drop |
| `public_key` / `preshared_key` | base64/hex; a zero PSK is "none" |
| `address` | comma-separated CIDR list; a bare IP means `/32` (v4) or `/128` (v6) |
| `mtu` | config value clamped to `[1280, 1420]`, else **1420** (matches `inject_singbox`; xray hands `conf.Mtu` unchanged to its netstack device, `Xray-core/proxy/wireguard/client.go`). This is the **inner IP MTU**, the TUN-MTU role in `wireguard-go` (which caps it only at `MaxContentSize` = `MaxSegmentSize − 32`, i.e. 65503 on default/Android builds, `queueconstants_default.go:17` — the config value is the authority). One transport record carries exactly one inner IP packet ≤ MTU, and the sealed datagram is that packet **plus** the 16-byte header, the 16-byte tag and the padding — a 1420-byte inner packet leaves as a ~1456-byte UDP datagram (never cap the payload at `MTU − 32`; §2.1). **No MSS constant**: smoltcp derives `local_mss = ip_mtu − ip_header_len − 20` and uses `min(local_mss, peer SYN MSS)` — `smoltcp-0.14.0/src/socket/tcp.rs:2319-2320` |
| `reserved` | exactly 3 bytes (comma decimals or base64); any other length is ignored, as the builders already do |
| `persistent_keepalive` | seconds; `0`/absent = off |
| `dns` | list of IPs; resolution policy in §3.7 |
| endpoint | the profile's `EndpointEssentials`; a hostname is resolved **locally** (same rule as `dial_direct`) |
| peer | exactly one, allowed IPs `0.0.0.0/0` + `::/0` (evidence: `WireguardConfig` has one `public_key`; `inject_xray` emits a single peer) |

### 3.4 Dispatch and lifetime

`connect_shape` stays `DeviceTunnel`. `protocol::connect` keeps its `not_impl` arm as an unreachable-by-construction guard (a test asserts a WireGuard row never reaches the stream dispatcher).

`inbound::outbound::dial` gains a branch before `mux_pool`: a `ProxyOutbound` whose kind is `WireGuard` opens a flow on a shared device:

```text
WgPool::open(&params, target) -> BoxStream
  key   = (endpoint, public_key, private_key hash, address list, mtu, reserved)
  value = Arc<WgDevice> owning: UDP socket, core Tunnel, smoltcp Interface, SocketSet, driver task
```

One device per key, because a WireGuard peer keeps one session per key — a second session with the same key replaces the first (`ZeroNet/wg_stack.rs` header). Idle device teardown after 5 minutes with no open flow and no keepalive configured.

Chain rule: WireGuard can only be the **single** link. It cannot ride a base tunnel (it needs a raw UDP socket and an IP interface) and it cannot carry a later link (it is not a byte stream). `chain.rs` refuses both, next to the existing QUIC-family refusal.

### 3.5 Routing

WireGuard's cryptokey routing sends every destination to the sole peer, but `smoltcp` still
needs a route: with a `/32` (or `/128`) interface address the target is neither on-link nor
routed, and `smoltcp` emits no packet at all. The interface therefore installs a **default
route per family**, gateway = the tunnel address itself — the same shape both Rust
references use (`ferrox-app/src/wg_stack.rs::add_default_routes`, `ZeroNet/wg_stack.rs:897-903`).

### 3.6 The driver

One tokio task per device, woken by:

1. the UDP socket (readable → `Tunnel::receive` → decrypted IP packet into the smoltcp device's inbound queue);
2. a flow command (new TCP SYN / UDP datagram / socket data);
3. a timer: `min(iface.poll_delay(now, &sockets), tunnel.next_deadline())`.

After each wake: `iface.poll(now, &mut device, &mut sockets)`, then drain every frame the device's `TxToken` produced through `Tunnel::send` into the connected UDP socket in one `send` per sealed packet. No polling loop and no per-packet scratch buffer: one MTU-sized receive buffer and one seal buffer, both reused (`NETWORK_BUFFER` = MTU + 64 headroom).

Backpressure is bounded channels, not unbounded queues: 8 × 16 KiB chunks per direction per flow; a slow reader closes the TCP window instead of growing memory.

Two driver rules the end-to-end rows proved necessary (both are "poll again", not protocol):
a write the socket could not take yet is retried **after** the poll, and a successful retry
`continue`s the loop so the bytes it queued become frames before the task sleeps (smoltcp
does not schedule a wake for queued output), and every socket-received datagram re-enters
the loop through the poll before the next `select!`.

### 3.6 Flows

- **TCP**: one smoltcp socket per SOCKS CONNECT, `TcpSocket::connect(remote, ephemeral local port)`. `TcpFlow` implements `AsyncRead`/`AsyncWrite` over two bounded channels + a `Notify`; `poll_shutdown` completes **when the FIN is queued**, not when the socket reaches `Closed` (the `netstack-smoltcp` patch-4 bug). Connect timeout 12 s. On drop with a live socket: discard incoming data, `abort()` (RST) — the orphan will not linger two hours.
- **UDP ASSOCIATE**: one smoltcp UDP socket per association; each SOCKS5 UDP datagram is one inner IP/UDP packet and a reply is one SOCKS5 UDP response with the source address taken from the inner IP header. It rides the chain's datagram path, not the stream one: `connect_chain_udp` short-circuits a single `WireGuard` link into `pool::open_udp` before any transport is dialled, and the association is `PacketTunnel::WireGuard` whose writer reports `requires_destination` (a datagram with no `IP:port` cannot be sent — sending it to the session header would silently misroute).
- **Limits**: live sockets bounded by `ServerConfig.max_connections` (`0` = `inbound::DEFAULT_MAX_CONNECTIONS`); past the bound a SYN is answered with RST and nothing is allocated. A socket still in `Listen`/`SynReceived` after 120 s is reclaimed; a retransmitted SYN for a live four-tuple joins that socket instead of creating another; rings are 64 KiB each way (≈ 192 KB/connection).
- **IPv6**: the interface holds every configured address; v6 targets take the same path, and smoltcp's own derivation covers the larger v6 header.

### 3.7 DNS

Policy (grilled): resolve through the tunnel when `dns` is non-empty and `remote_dns_resolve != Some(false)`; use the local resolver only when **no configured resolver is alive**, where alive means "answered within `RESOLVER_ALIVE_WINDOW` (600 s)". There is no other fallback and no per-lookup silent downgrade: the fallback happens at most once per session and logs one WARN. A resolver set that was alive and now is not is exactly the fallback case — the leak is bounded to that state, which is what the user's rule permits.

Implementation (**amended 2026-11-26 during T6**): `leas-dns` owns the policy, the liveness window and the fallback, and the caller owns the wire through one trait. The first draft planned a hickory `ConnectionProvider` arm (`HybridConn::Plain`); building it showed that seam needs a full `DnsRequestSender` implementation plus a 53-port `NameServerConfig` per server, while the wire it would carry is the tunnel's own UDP flow. The delivered shape is smaller and keeps one owner:

1. **`PlainResolver`** (`crates/leas-dns/src/lib.rs`): `lookup(hostname, ipv6) -> Future<Result<Vec<IpAddr>>>`, a caller-supplied transport that must not apply a fallback of its own.
2. **`DnsResolver::set_plain_resolver` / `clear_plain_resolver` / `has_plain_resolver`**: an `ArcSwapOption<PlainEntry>` beside the stamp pool; `PlainEntry` carries the resolver and its last-success `Instant`.
3. **`lookup_ip_scoped`** returns `(Box<[IpAddr]>, DnsScope::{Tunnel, Pool, System})`; `lookup_ip` delegates. Order: an IP literal answers as `Tunnel`; an installed plain resolver answers (and stamps liveness) or, when it fails **with a success inside `RESOLVER_ALIVE_WINDOW`**, returns that error — a broken tunnel is an error, not a silent local lookup; only a transport with no answer inside the window falls through to the pool (`Pool`) or the OS configuration (`System`).
4. **`leas-native` implements `PlainResolver`** over its netstack UDP flow (T7), so the wire codec lives with the transport that needs it and `leas-dns` stays free of tunnel types. DoH/DoT are **not** reachable through the tunnel in this slice (they would need TLS-over-smoltcp); plain UDP is the supported set.

`WireguardConfig`'s fields already exist and are identity-covered, so no schema or identity change.

### 3.8 Capability, probe, telemetry

- `capability::support_reason` loses the WireGuard arm; `SUPPORT_REVISION` **3 → 4** (`capability.rs:54`) so `Database::clear_stale_capability_verdicts` re-opens the rows once (no schema change — the marker is `app_meta.capability_version`; the TUIC work took 3 and no other armed kind claims a bump).
- `capability::tests::non_native_kinds_unsupported` drops `WireGuard` (18 → 17 kinds).
- `probe.rs` needs no new path: a Real Test is a SOCKS CONNECT plus one HTTP request, so through the device it exercises handshake, netstack TCP, and — because the Real Test host is a name (`/generate_204`) — tunneled DNS.
- Trace/telemetry, Sniffer accounting and byte counters reuse the existing relay bookkeeping; `WgPool::open` returns a `BoxStream`, so `inbound::outbound::relay` is unchanged.

### 3.9 Errors

`NativeError` gains no new variant. Mapping: handshake timeout → `NativeError::Timeout { step: "wireguard handshake", .. }`; MAC/cookie/auth failure → `NativeError::Protocol`; netstack TCP refusal/timeout → `NativeError::Dial` or `Timeout { step: "wireguard tcp" }`; DNS policy failure → the existing DNS error surface. SOCKS reply codes come from `inbound::reply_for`, unchanged.

## 4. Decisions (grilling, 2026-11-26)

| # | Question | Answer |
| --- | --- | --- |
| Q1 | scope | **B** — full parity outbound (not codec-only) |
| Q2 | target DNS | tunnel via `dns`; local only when no configured resolver is alive |
| Q3 | codec owner | **own** sans-I/O core; boringtun only as a last-resort test oracle |
| Q4 | DNS seam owner | **extend `leas-dns`** (plain-IP arm + injected sockets), not a second resolver |
| Q5 | acceptance bar | **A** — TCP + UDP ASSOCIATE + tunneled DNS + `reserved`, v4 and v6, badge flips |
| — | peers | single peer, `0/0` + `::/0` (config has one `public_key`) |
| — | AmneziaWG / kernel TUN | out of scope |
| — | `ConnectShape` | stays `DeviceTunnel` |

## 5. Verification

### 5.1 Unit (no runtime, no clock)

- `kdf.rs`: KDF1/2/3 vectors; `handshake.rs`: a full exchange between two in-memory `Tunnel`s produces the same keys on both sides, and an initiation with a flipped byte fails `mac1`;
- `transport.rs`: seal/open round-trip, counter/nonce layout, padding strip, per-record truncation refused, replay window accepts in-order and out-of-order within 8128 and refuses a duplicate and a counter at the ceiling (`#[rstest]` rows);
- reserved bytes: a message with `reserved = [1,2,3]` verifies `mac1` only after zeroing (the stamp-after-MAC rule) and parses to type 1/2/4;
- timers: with injected `now`, a lost response retransmits at 5 s, gives up after 90 s, rekeys at 120 s and refuses sends at 180 s.

### 5.2 E2E (delivered in `crates/leas-oracles/tests/wireguard.rs`)

The delivered oracle is a **`boringtun 0.7.1` responder as a dev-dependency** (ADR 0019 permits it: test-only, never a runtime dependency) with a `smoltcp` interface and a TCP echo listener, all on loopback — no core binary, no TUN, no `CAP_NET_ADMIN`. The sing-box `wireguard` endpoint was rejected as the oracle because a peer's TCP connection to the endpoint's own interface address needs host routing (or `system: true`) to reach a local echo, which makes the harness depend on the host's network stack rather than on our client.

The rows now live in `crates/leas-oracles/tests/wireguard.rs` (the repo's rule is
that every e2e row lives in `leas-oracles`), and two **real-core** rows live in
`crates/leas-oracles/tests/wireguard_oracle.rs`:

- **sing-box** `wireguard` endpoint (`system: false`, so gVisor, no TUN/root): the
  client dials the endpoint's own tunnel address (`10.66.0.1:80` — any other
  destination is dropped by the userspace netstack), and a 1.11 route action
  (`action: route`, `override_address: 127.0.0.1`, `override_port: <echo>`)
  lands it on a loopback HTTP echo.
- **xray-core** `wireguard` **inbound** (`noKernelTun: true`) — xray registers the
  protocol for inbounds too (`infra/conf/xray.go`, `IsClient: false`). Its
  `freedom` outbound applies `defaultBlockPrivateRule` to a wireguard inbound's
  traffic, so the row routes into a local SOCKS5 stub instead.
- **mihomo** has no wireguard listener (`listener/` has none), so it cannot be a
  server oracle; it stays a client-only reference.

Both rows pass in ~0.3 s; they need the pinned cores and are `#[ignore]`d, so a
machine without binaries stays green. No privileges, containers, or
testcontainers are involved: the pinned binaries are spawned as child processes
and both servers terminate the tunnel in user space.

Hermetic rows (10/10, 11 s): the responder accepts our initiation (handshake transcript + MACs), a TCP echo round trip through the stack, and an 8 KiB echo while every 5th datagram is dropped in each direction — the `smoltcp` loss-recovery gate. UDP ASSOCIATE and tunnel DNS remain unit/policy-tested (§5.1) rather than e2e, because both need a second responder-side TCP/UDP service that adds nothing the two passing rows do not already prove about the wire.

### 5.3 Gate

`just quality-gate code` (fmt + clippy workspace `-D warnings` + nextest). `cargo hakari` after the `Cargo.lock` change (new `smoltcp` edge). The `leas-native` and `leas-dns` unit rows run in the default members; the e2e rows live in `leas-oracles`.

### 5.4 Docs after implementation

`docs/reference/native-core.md` three rows: the support table line 162 (`planned` → `done` for client/probe), the divergent-shape note line 183, and the shape table line 266 (the "needs a TUN or userspace device abstraction" blocker is resolved by §3.5). `docs/reference/protocols.md` §12 already documents parsing/injection and needs no change. `docs/architecture/decisions.md` + **ADR 0019** (§8), `AGENTS.md` (one convention bullet: L3 outbounds own a userspace stack and one shared device per profile identity), `leas-hakari`.

## 6. Out of scope

Server role; multi-peer / `allowed_ips` capture; AmneziaWG junk packets and H-magic type words; kernel WireGuard via netlink; TUN devices; route installation or system-wide VPN mode; DoH/DoT/DoQ through the tunnel; WireGuard as an intermediate chain link; roaming (the UDP socket stays connected to the configured endpoint, so a server-side address change is a new session, not a roam).

## 7. Risks and limits

- **smoltcp TCP recovery** was the one unproven part; §5.2's loss row now passes on stock 0.14, so the fork is not needed. Standing context: `shoes` pins a fork precisely because stock smoltcp loses ACK sequencing during partial retransmission; `ZeroNet` instead patched the *driver* for socket lifecycle. `smoltcp 0.14.0` is the current release and the fork's series tracks upstream **after** 0.14, so a future regression here is not something a version bump fixes: the loss row is the guard, and the escalation path (if it ever reddens) is a `[patch.crates-io]` to the cfal fork with its own ADR.
- **Memory**: ≈ 192 KB per live connection at 64 KiB rings; the live-socket cap is the guard, and it must be the same number the listener already enforces.
- **`reserved` semantics** are grounded in `ferrox` source, not in a live WARP test; the byte-level rule is unit-tested, the end-to-end WARP path is not.
- **Alive-window DNS fallback** is a deliberate, bounded leak: one WARN, one session, only while no configured resolver has answered in 10 minutes.
- **Two-crate change**: `leas-dns` grows a provider arm the app never uses; if `HybridConn` turns out to be DNSCrypt-specific rather than a generic `Connection`, arm 2 becomes a second `Connection` impl (contained, but it is the line item that decides the size).

## 8. ADR signals

Before merge, **ADR 0019** (0018 is the last) is required for the durable decisions this spec makes: **`smoltcp` becomes `leas-native`'s IP stack owner for L3 outbounds, and the DNS owner gains a plain-IP transport arm supplied by the caller**. It fixes: the dependency and its pin policy (0.14.0; any bump or the cfal fork only behind a loss-recovery test), the rule that an L3 outbound owns a device + driver task shared per profile identity, and the rule that target resolution inside a tunnel is the tunnel's job, with local resolution permitted only under the alive-window condition above, and the type-level shape of the DNS seam: a caller-supplied `PlainResolver` transport behind `leas-dns` policy, not a generic `DnsResolver` and not a hickory provider variant.
