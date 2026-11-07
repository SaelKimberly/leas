# Native core and TLS engine

This reference answers one question: which protocols and transports the in-process core serves today, and how each capability was verified. Every row names the crate path that implements it, so a claim can be checked against the code.

It does not cover the JA4 roster evidence (owned by [`tls-fingerprint-roster.md`](tls-fingerprint-roster.md)), the crypto dependency posture and hazmat inventory (owned by [`crypto-dependencies.md`](crypto-dependencies.md)), the per-protocol wire and share-URL reference (owned by [`protocols.md`](protocols.md)), or the decision to run the core in-process (owned by [`../architecture/native-core-integration.md`](../architecture/native-core-integration.md)).

## Purpose

The leas client is native-only: every connect runs the in-process core, built on `leas-proto` typed configs. The subprocess path (spawning xray-core or sing-box, writing JSON configs, talking gRPC) survives only in the dev-only `leas-oracles` crate, where the e2e harness runs those binaries as real servers and config generators. The TLS engine exists because stock rustls ClientHellos are instantly identifiable; browser-fingerprint mimicry and REALITY need a ClientHello the client fully controls.

The core is primarily a client. Each connect dials a remote proxy. It also hosts local inbounds (`crates/leas-native/src/inbound/`): a SOCKS5 listener with UDP ASSOCIATE, an HTTP CONNECT listener, and a mixed listener that selects between the two on the first byte. An inbound accepts, routes through `leas-route`, then forwards to a direct, block or proxy outbound; the proxy outbound reuses the native client tunnel. Remote server-side protocol behavior stays with xray-core and sing-box, which the e2e harness runs as real servers.

The engine negotiates TLS 1.3 by default. A TLS 1.2 ServerHello selects the engine's TLS 1.2 path (ECDHE plus AEAD), so legacy TLS 1.2-only servers are reachable. CBC and static-RSA suites are refused by policy and named in `crypto::tls12::REFUSED_TLS12_SUITES`; [`crypto-dependencies.md`](crypto-dependencies.md) §3 owns that decision. REALITY stays 1.3-only: a 1.2 ServerHello returns `TlsError::RealityFallback` and the caller runs Spider-X.

The rustls client path is gone. Inside the native core, rustls remains in two places: the server-side test double (unit tests and the e2e `tls_echo` destination), and quinn's internal QUIC TLS for the xhttp h3 dial and the Hysteria2 dial. No client-facing TCP TLS path bypasses `leas-tls`.

## Principles

- **Xray composition order, one layer stack.** `dial → security → transport upgrade → protocol → tunnel`, with TLS outermost: a ws or grpc transport frames inside the engine TLS session. mKCP is a dial-end exception. It is a UDP dial, not an upgrade: `connect` gains the kcp arm (`crates/leas-native/src/transport/kcp/`), `upgrade` stays passthrough, and the security layer wraps the KCP stream as it wraps TCP. xhttp with a single `h3` ALPN is the second exception: the QUIC dial replaces dial, security and upgrade (`transport::is_self_contained`), and the engine TLS never wraps QUIC.
- **Config source of truth is `leas-proto`.** No config model lives in native. `NativeConnectParams` (`crates/leas-native/src/context.rs`) wraps the typed `ProtocolConfig` plus `EndpointEssentials`; the host and port are injected from the endpoint at connect time.
- **`leas-tls` is ring-only.** No aws-lc-rs, no `rand`, no `unsafe`. CSPRNG enters through a crate-local `SecureRandom` seam. Two documented exceptions: `x25519-dalek`, because ring's `EphemeralPrivateKey` is single-use and REALITY must agree twice with one scalar, and RustCrypto `ml-kem`, because ring has no post-quantum KEM. `zeroize` is not an exception: it supplies no algorithm.
- **Secrets are wiped, and the wipe is a dependency contract.** Every owned key buffer is `Zeroizing` or `ZeroizeOnDrop`; the per-crate `zeroize` features are listed explicitly in both manifests, and losing one compiles clean and silently stops wiping. The contract, the deliberately unwiped set (decision 19 in [`AGENTS.md`](../../AGENTS.md)) and the re-check command are owned by [`crypto-dependencies.md`](crypto-dependencies.md).
- **Explicit absence beats silent fallback.** Every protocol kind, transport and security variant has a module and a dispatch arm. An unsupported combination returns `NativeError::NotImplemented` naming the missing feature (`crates/leas-native/src/protocol/mod.rs`, `crates/leas-native/src/transport/mod.rs`).
- **The capability gate mirrors dispatch, not xray's feature set.** `capability::support_reason` (`crates/leas-native/src/capability.rs`) is the connect-time predicate; `supported` is its bool form. Unknown values fail closed: a false positive is a dead or hanging connection where a fallback would have silently hung.
- **`leas-proto` changes only deliberately.** The VLESS `mlkem768x25519plus` parser and hybrid curve names are the one instance so far.
- **Crate-backed cryptography, hazmat sites governed.** ring and RustCrypto supply every primitive; both crates are `#![forbid(unsafe_code)]`. Every non-default site and every triaged advisory is inventoried, with an oracle and a retirement trigger, in [`crypto-dependencies.md`](crypto-dependencies.md).

## Verification tiers

| Tier | Gate | What runs | Evidence |
|------|------|-----------|----------|
| 1: offline | `cargo test -p leas-tls -p leas-native --lib`; `cargo nextest run -p leas-tls -E 'test(every_roster_hello_has_rfc_minimal_extension_bodies)'` | Wire encodings, RFC 8448 key-schedule vectors, GREASE pairing, JA3/JA4 goldens, VMess Go byte vectors, rustls-server interop, multi-record reassembly, the TLS 1.2 client path (X25519 + secp256r1 ECDHE, AEAD key block, explicit nonce, DOWNGRD sentinel, RFC 7627 EMS guards), Spider-X fallback, transport framing (httpupgrade header set, xhttp chunk/seq/pacing and padding, v2rayhttp method and authority), vision codec with a hermetic fake vision server, VLESS UDP framing and packetaddr, the ECH inner/outer hello round trip, and the mKCP wire, session and mask vectors | Hermetic; th…
| 2: live grader | `cargo run -p leas-tls --example grader -- --profile <id>`; `cargo run -p leas-tls --example grader -- --roster [--family <name>] [--sample]`; `cargo test -p leas-tls --test tls_peet_ws -- --ignored`; `cargo run -p leas-tls --example probe_host -- <host> <port> <sni> [attempts] [alpn,list] [--verify]` | ClientHello graded against tls.peet.ws, and a real `host:port` dial through the engine's plain-TLS path. `probe_host` separated engine faults from server faults in the 2026-09-15 batch (the `record too large` rows handshook 60/60, so the path was transient) and in the 2026-09-16 batch (the `no certificate` rows reproduced 3/3, and a TLS-1.2 P-256-only host failed 3/3 until secp256r1 ECDHE landed) | Needs network |
| 3: real-core e2e | `cargo test -p leas-oracles --test vless --test vmess --test trojan --test hysteria2 --test shadowsocks` | Native client against spawned xray-core 26.3.27 and sing-box 1.13.16, over the transport, TLS-variant, UDP, mux, XUDP, mKCP, XHTTP/3 and ML-KEM axes below | Hard-fails on a core version mismatch; `build.rs` fetches the pinned binaries (override `LEAS_CORE_BIN_DIR`) |
| 3a: sing-box differential | `cargo test -p leas-oracles --test plugin_3a -- --ignored` | The native SIP003 framing against sing-box's in-process `v2ray-plugin` client on the same server | Structural, not raw-byte: normalized WS head, mux New/TCP/domain frame class, and summed mux `data_len`. The random WS key and the target port/session id are masked because they must differ |
| 3b: plugin oracle e2e | `just plugin-bins` then `LEAS_PLUGIN_BIN_DIR=<dir> cargo test -p leas-oracles --test plugin_sip003 -- --ignored` | The native client against a real `v2ray-plugin` v1.3.2 and `obfs-server` v0.0.5, over TCP | Rows 1, 2, 3, 4, 4b, 5 and 15. Row 4b is the negative proving the mux target field is inert; row 15 is the negative proving certificate verification is real |

Tier 1 is hermetic and is the CI gate. Tier 2 needs network. Tier 3 needs the
version-pinned core binaries (`XRAY_VERSION` and `SINGBOX_VERSION` in
`crates/leas-oracles/src/pins.rs`); `leas-oracles`'s `build.rs` fetches them into
`OUT_DIR/core-bin` (set `LEAS_CORE_BIN_DIR` to use existing binaries, or
`LEAS_ORACLES_SKIP_DOWNLOAD=1` to compile-check). Tiers 3a and 3b are opt-in
operator runs, not CI dependencies.

### What the offline gates cannot see

`tests/generated_ja4_gate.rs` validates a built hello against this crate's own parser and the JA4 projection. Tier 2's grader validates it against tls.peet.ws, a Go peer that ignores extensions it does not implement. Neither can see an extension body the RFC forbids. On 2026-09-17 two such bodies shipped: `encrypted_client_hello` with a 0-byte body (36 generated rows) and `compress_certificate` with an empty algorithm list (28 rows). Cloudflare and Google answered `alert 2 50 (decode_error)`, which made every firefox, safari and ios preset unprobeable and unconnectable there. Two gates close it: the RFC-minimum body sweep in tier 1 (`profiles::tests::every_roster_hello_has_rfc_minimal_extension_bodies`) and `cargo test -p leas-tls --test strict_peer_presets -- --ignored` in tier 2, which handshakes a Cloudflare front with every preset `profile_for` resolves.

### Fingerprint ids without a roster row are approximated

`security::fingerprint::resolve_fingerprint` (`crates/leas-native/src/security/fingerprint.rs`) is the single decision point, read by the capability gate and by the row label, so the two cannot drift. Policy as of 2026-09-22: an id with no roster row is probed with the engine default and marked, never refused.

| `fp` | Reading | Approximation |
|------|---------|---------------|
| absent, `""`, `unsafe` | No fingerprint requested; the engine default is the shape asked for | no |
| `chrome`, `firefox`, `safari`, `edge`, `ios`, `random(ized)` | Resolves to a roster row | no |
| `qq`, `android`, `360`, `hellochrome_120`, any unknown id | Requested, no roster row | yes, the row probes with the default hello |

On the reference feed this moved 1,165 previously refused links to 924 approximated plus 257 honoured, with 0 refusals remaining (2026-09-22). The marker renders as a trailing `~` on the Test cell and on the panel's per-link shape cell, derived from the `security_fp` column; no new persistence. The capability gate no longer refuses a fingerprint id, and the old `security_reason` fingerprint arm was deleted rather than left returning `None`.

`profile_for` maps the honoured ids to concrete roster rows: `chrome`, `chrome-randomized` and `random` to Chrome 130 (the hand-declared `chrome_130`), `firefox` to Firefox 128 on Linux, `safari` to Safari 17 on macOS, `edge` to Edge 106 on Windows desktop, `ios` to Safari 26 on iOS phone. The roster itself and its fidelity evidence belong to [`tls-fingerprint-roster.md`](tls-fingerprint-roster.md).

## Crate maps

### leas-native (`crates/leas-native/src/`)

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | `Stream`/`BoxStream` seam, `connect()` entry, `NativeTunnel` |
| `chain.rs` | `connect_chain`: fold the layer stack. `dial_transport` and `finish_chain` split the fold at the probe's stage boundary |
| `probe.rs` | The real-ping primitive: one HTTP request through a native tunnel. Two stages with independent budgets (spec `2026-10-21-merged-test-pipeline-design` D12): the transport stage, the dial to the proxy server bounded by `ProbeRequest::transport_timeout` and reported as `ProbeResponse::transport_span`, then the protocol plus probe stage (security handshake, transport upgrade, protocol handshake, target TLS, request head) bounded by `ProbeRequest::timeout`. The budgets are not a split of one total; a row's worst case is their sum (5 s + 5 s by default). The transport span is the measurement that separates "the server is dead" from "the server is up and the config is not" |
| `context.rs` | `LinkContext`, `NativeConnectParams` (wraps proto types) |
| `addr.rs` | `TargetAddr` (domain/IP plus port) encode and decode |
| `sockopt.rs` | Outbound socket options on the safe surface only (`socket2`): `TCP_USER_TIMEOUT`, keepalive, `SO_REUSEPORT`, `IPV6_V6ONLY`, `TCP_NODELAY`, `TOS`. `TCP_USER_TIMEOUT` and `SO_REUSEPORT` have no `socket2` method on Windows and are no-ops there. `SO_MARK`, `SO_BINDTODEVICE` and `TCP_CONGESTION` need an ADR because the crate forbids unsafe |
| `inbound/` | Local SOCKS5 server (`Socks5Inbound`, RFC 1928 plus RFC 1929 auth): accept, route through the `leas-route` `Engine`, dispatch to a tagged `Outbound`/`OutboundKind` (Direct, Block or Proxy; the proxy reuses `crate::connect`). TCP CONNECT plus UDP ASSOCIATE (`Socks5InboundConfig::udp`, default on): per-datagram routing, per-family direct sockets, and a proxy leg task owning a split `PacketTunnel` (a stream carrier's `recv` is never raced in a `select!`). The association is pinned to the control peer, expires without a first datagram, and ends on control-TCP EOF; per-datagram failures drop the datagram only. BIND is refused `0x07`, `HijackDns` drops the datagram (TCP `0x02`) |
| `inbound/http.rs` | Local HTTP CONNECT proxy (`HttpInbound`, same `Engine` to tagged-outbound path). CONNECT-only: absolute-form requests are not forwarded (`501`), CONNECT without `host:port` is `400`, a head over 16 KiB is `431`, a missing or malformed Basic credential is `407` with `Proxy-Authenticate: Basic realm="leas"`, Block or Reject is `403`, an unknown outbound tag or failed dial is `502`, and success is a bare `200 Connection Established`. Optional Basic auth (`HttpInboundConfig::with_auth`); both inbounds warn once at bind time on a non-loopback bind without auth |
| `inbound/mixed.rs` | Local mixed inbound (`MixedInbound`): one listener for SOCKS5 and HTTP CONNECT, selected by the first byte (`0x05` selects SOCKS5, anything else HTTP CONNECT), matching xray-core's `mixed` and sing-box's `TypeMixed`. Each handler keeps its own config, so auth and trace kind follow the negotiated protocol; the listener binds at the SOCKS config's address |
| `transport/` | `connect` is a TCP dial (ws, grpc, httpupgrade, xhttp, v2rayhttp) or a fresh-UDP mKCP dial (`kcp/`) or the QUIC dial (`quic.rs`, the shared quinn endpoint, TLS verification and 0-RTT helpers used by both the xhttp h3 arm and the Hysteria2 client). `upgrade` runs the framing handshake inside the secured stream |
| `transport/kcp/` | xray's KCP fork over UDP: `wire.rs` (segment codec, one segment per datagram, conv from a process-global counter), `session.rs` (windows, retransmit, RTO, congestion), `stream.rs`, and `mask.rs` (see the transport table) |
| `security/` | `wrap()` builds an engine `TlsConfig` and runs `leas_tls::client::connect`; `fingerprint.rs` (id parser, `profile_for`, `resolve_fingerprint`, `WebPkiVerifier` builder plus test CA); `reality.rs` (`HelloProvisionerChoice`, pbk/sid decoders) |
| `protocol/` | 20 protocol modules. Implemented: `vless`, `vmess`, `trojan`, `hysteria2` (self-contained QUIC dial), `ss` (classic AEAD, 2022-blake3 and the legacy stream set) and `socks` (client handshake). The other 14 return `NotImplemented` with the feature name. `vless/vision.rs` is the `xtls-rprx-vision` codec; `vless/header.rs` carries the protobuf flow addon and the command byte (0x03 Mux carries no destination bytes); the v1.mux.cool frame codec and `MuxClient` live in `transport/mux.rs` and are re-exported by `protocol/vless/mod.rs`, so the SS plugin mux shares one implementation |
| `transport/mux.rs` | v1.mux.cool frame codec plus `MuxClient`: `[2B meta_len][metadata][2B data_len][payload]` frames, eager New, event-driven Keep/End, tunnel-level KeepAlive every 10 s, 8 KiB chunks, `SessionStream` and `UdpSession` (`open_udp_session` carries a fresh random 8-byte `GlobalID` on the New frame) |
| `crypto/` | Shared primitives: `aead.rs` (`SsAead` on RustCrypto plus `NonceCounter`), `kdf.rs` (the three Shadowsocks KDFs: HKDF-SHA1 for the classic subkey, BLAKE3 `derive_key` for the 2022 session subkey, `EVP_BytesToKey` MD5 for the classic password to key step), `legacy_stream.rs` (AES-CFB, AES-CTR composition, RC4, used by the Shadowsocks legacy methods and the VMess legacy header), `salamander.rs` (Hysteria2 obfs). ML-DSA verification lives in `leas-tls`, not here |
| `shape.rs` | `ConnectShape`: uniform versus divergent connect paths |
| `leas-oracles::e2e` | case, config, core, harness and variant: real-core scenarios, including the Shadowsocks server-config builders (xray `settings.method`/`password` with a widened `network` for UDP rows, sing-box top-level `method`/`password`, and the xray-only TLS-row gate) |

### Telemetry contract (`crates/leas-native/src/telemetry.rs`)

`Telemetry` is the native to TUI feed, cloned into every connection task. It has three surfaces.

- **Logs.** `NativeEvent::Log`; a full queue drops the line and counts it.
- **Traces.** `TraceEvent::{Opened, Closed, Failed}` on their own queue, so a log burst cannot evict a leg's open/close pair. `Opened` carries the destination as the client sent it (`host:port`), `Closed` carries the leg's bytes, duration and error, and `Failed` carries a refusal that never reached a relay (`TraceFailReason`: `auth`, `malformed`, `blocked`, `rejected`, `hijack-dns`, `no-outbound`, `dial`). A failure touches no byte total.
- **Traffic.** Shared atomics drained every 3 s into `CoreEvent::StatsUpdate` (`STATS_INTERVAL_SECS = 3`, `crates/leas/src/ops/native_connect.rs`).

Per-host accounting (spec `2026-11-03-sniffer-pane-design`):

- The host key is the destination as sent, port stripped, no local DNS (`example.com` and `1.1.1.1` are separate rows; IPv6 literals lose their brackets). The table is capped at 1000 hosts, least-recently-active evicted (`HOST_TABLE_CAP`).
- A relayed TCP leg registers its byte atomics in an open-leg map and folds them into the host row on close. A leg is either open or folded, never both. `conns` counts accepted legs.
- UDP accounting is per datagram: `udp_sent` and `udp_received` add payload bytes to the destination or source host (one map lookup, no allocation for an inline key), `udp_conn` counts an association once per host it touches, and `udp_dropped` counts undelivered payloads (malformed, blocked, rejected, hijack-dns, queue cap or full, unresolvable destination, carrier refusal, send error) as session-global counters. A datagram accepted into a proxy leg and lost upstream is counted in both `up` and the drop counters by design; the drop slice is a failure signal, not a conservation equation.
- `Telemetry::snapshot()` merges folded rows with still-open legs and sorts by total bytes descending. `SnifferSnapshot.hosts` is a `SmallVec<[HostStat; 16]>` of `HostStat { host, up, down, conns, failed }`. The native session emits a snapshot every second as `CoreEvent::SnifferSample` (`SNIFFER_INTERVAL_SECS = 1`).
- Accounting is session-only and in memory: no table, no persistence, and no coverage for subprocess cores.

### leas-tls (`crates/leas-tls/src/`)

| Module | Responsibility |
|--------|----------------|
| `spec/` | Declarative `ClientHelloSpec`/`ExtensionSpec`/`SessionIdSpec`, RFC 6066 and RFC 8446 wire encodings, GREASE (RFC 8701), and the hybrid key-share encoding (`X25519MLKEM768`: client share is ML-KEM ek(1184) followed by X25519 pub(32)) |
| `profiles/` | Two-tier roster: the hand tier (`hand_selected.rs`, `spec!`-declared, 2 wire-exact profiles, `chrome_130` and `edge_106`) and the generated tier (`generated/`, emitted by `gen_specs.py --emit`, 69 JA4-faithful entries). The resolver merges both tiers with hand rows winning on identity overlap. Fidelity evidence: [`tls-fingerprint-roster.md`](tls-fingerprint-roster.md) |
| `fingerprints/` | Identity selector: `Fingerprint { browser, version, os, device }` resolved with next-modern semantics over the two-tier table, plus a cross-triple os-drop fallback (an exact triple miss retries with the os dropped; desktop hellos are OS-independent within a family). It never returns a different browser and never an older version; an unknown combination errors listing what is resolvable. `FingerprintBuilder` overrides ciphers, extensions, curves, ALPN, signature algorithms and the GREASE policy. `catalog/catalog_data.rs` is the frozen ja4db-export snapshot (2026-05-15), evidence only |
| `client.rs` | Unified engine API: `TlsConfig { mode, server_name, alpn, curves, ech, rng }`, `TlsMode::{Plain, Reality}`, and one `connect(stream, &TlsConfig)` entry. ALPN entries are opaque bytes (RFC 7301 §3.1) |
| `hello/` | `build_hello`/`to_record` (GREASE pairing, 512-byte record padding), `build_hello_ordered` (family- and era-scoped extension permutation: Chromium 108 and later shuffles per connection, Firefox and Safari keep spec order; padding and `pre_shared_key` are pinned last), `parse_hello` (bounds-checked on every length field) |
| `ech.rs` | Encrypted ClientHello (RFC 9849) client: `ECHConfigList` parse and selection from the link's `ech=`, the outer/inner hello split (`ClientHelloOuter` carries the public name plus the `fe0d` extension, `ClientHelloInner` the real SNI with TLS 1.3-only `supported_versions` and the `0x01` inner marker), HPKE base-mode sealing of the padded inner body (`"tls ech" || 0x00 || ECHConfig` info, AAD is the outer hello with the payload zeroed), and the §7.2.1 acceptance confirmation. A server that answers the outer hello is a hard error, never a silent SNI leak. Only `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` and `AES-128-GCM` is implemented, which is what Cloudflare, Fastly and the browsers negotiate; a config with no such suite is refused by name |
| `crypto/` | Key schedule (RFC 8448-verified, streaming transcript so `transcript_hash()` is O(state); hybrid input is `pq || classical`; `update_traffic_secret` implements `traffic upd`), AEAD record keys (IV XOR sequence), the TLS 1.2 key block (`tls12.rs`: X25519 plus secp256r1 ECDHE, AES-GCM and ChaCha20-Poly1305 explicit-nonce AEAD), `X25519KeyPair` (low-order peer points refused per RFC 7748 §6.1), `mlkem.rs` (ML-KEM-768 via RustCrypto: pk 1184, sk is the 64-byte FIPS 203 seed, ct 1088, ss 32), `mlkem` and `mldsa` verification for REALITY (ML-DSA-65, FIPS 204), `hpke.rs` for ECH, and `fingerprint/` with the JA3 and JA4 encoders |
| `record/` | Record framing, `read_record`, `TlsStream<S>` (AsyncRead/Write, close_notify to EOF). Post-handshake `KeyUpdate` rotates the read key and acknowledges a requested update, and `poll_write` rekeys at the RFC 8446 §5.5 per-key record limit. `NewSessionTicket` is dropped: resumption is not implemented. Negotiated ALPN is exposed via `negotiated_alpn()`. Per-direction `set_write_direct`/`set_read_direct` bypass the record layer and hand the socket to the tunnel, which backs the vision Direct splice. TLS 1.2 record protection uses a plaintext-length AAD, an explicit nonce, and one write counter advanced only after a successful seal |
| `handshake/` | TLS 1.3 client handshake plus the TLS 1.2 fallback driver (`handshake/tls12.rs`), `server_hello.rs` (ServerHello and HelloRetryRequest parsing), `flight.rs` (the encrypted server flight), and the `ServerVerifier` seam. HelloRetryRequest is answered exactly once, on plain TLS only (REALITY's sealed session id binds the first hello, so an HRR there stays a typed error), only for a group the engine can produce (`x25519` 0x001D, `x25519mlkem768` 0x11EC) and only if `supported_groups` listed it; the cookie is echoed and the recorded RNG draws are replayed so `ClientHello2` differs only in `key_share`, `cookie` and `padding` |
| `verify/` | `WebPkiVerifier` (roots, CA DER, `insecure`, `pin_sha256`). The CertificateVerify signature is always checked, and the server signature algorithm is checked against the ClientHello offer on both TLS versions |
| `reality/` | `HelloProvisioner` and `SpecProvisioner` (any resolvable identity), the 9-step wire contract, `FixedChrome130Hybrid` (the wire-exact chrome_130 spec plus the X25519MLKEM768 share), `RandomEligible` (uniform per-dial pick over TLS 1.3 AEAD profiles with a 32-byte session id and a real X25519 share; the grafted hybrid is excluded as era-inconsistent), auth key and session seal, server auth, REALITY over the `X25519MLKEM768` share, and `SpiderConfig` with `spider.rs` (Spider-X HTTP/2 fallback) |
| `http2_profile.rs` | `Http2Profile`: one SETTINGS plus user-agent, `Accept` and `Accept-Language` table per browser family, consumed by the grader, the sweep and the spider so the h2 and header layer cannot contradict the hello |
| `http2/` | Minimal h2 layer for grading and Spider-X GETs |
| `error.rs` | `TlsError` and `Result` |

## Security layer

Every TLS and REALITY connect is engine-only: `security::wrap` builds an engine `TlsConfig` from the protocol's proto security config and calls `leas_tls::client::connect` with `TlsMode::Plain` or `TlsMode::Reality`.

| Path | Trigger | Mechanism | Status |
|------|---------|-----------|--------|
| Plain TLS | `tls` config | Engine `TlsMode::Plain`: a fingerprint-shaped hello from the `fp` profile (`None` resolves to `Fingerprint::default_for(Browser::Chrome)`), verified by `WebPkiVerifier` via `verifier_for(insecure, pin)` | done |
| REALITY | `reality` config | Engine `TlsMode::Reality`: fingerprint-shaped hello with any resolvable identity via `SpecProvisioner::try_from(&Fingerprint)`, sealed session id, X25519 auth key plus HMAC or Ed25519 server auth (no PKI), Spider-X on auth failure | done |
| Encrypted ClientHello | `tls` config with `ech=` | `leas_tls::ech`: `ECHConfigList` from the base64 link value, sealed inner hello, acceptance confirmed from `ServerHello.random`; a server that answers the outer hello is a hard error | done |
| Trust modes | `insecure`, `pin_sha256` | `with_insecure()` skips the chain walk; `with_pin(sha256(SPKI))` replaces chain and SAN but never skips the CertificateVerify signature | done |

The unified API is `TlsConfig { mode, server_name, alpn, curves, ech, rng }` with one entry point, `connect(stream, &TlsConfig)`. `TlsMode::Plain { fingerprint, verifier }` and `TlsMode::Reality { provisioner, public_key, short_id, mldsa65_verify, spider }` share one driver (`handshake::drive`), so plain and REALITY handshakes cannot diverge.

`ech=` is not merely parsed. `security::ech_config` (`crates/leas-native/src/security/mod.rs`) refuses an invalid value by name in the capability gate, so a config the client cannot honour fails loudly instead of leaking the SNI. Tier 1 covers the built hellos through a server-style decode and the acceptance confirmation; no tier-3 row exists, because no pinned core serves ECH on a local inbound.

**Spider-X fallback.** On a REALITY auth failure, when the server flight is a real certificate (a transparent proxy or possible MITM, mirroring xray-core `reality.go`'s `!Verified` path), the client keeps the established TLS session alive. It walks the real site with bounded HTTP/2 GETs (`SpiderConfig { paths, max_gets, request_interval }`, padding cookie, Referer chaining) so a DPI observer sees browsing traffic, then reports `TlsError::RealityFallback`, which native maps to `NativeError::Reality("REALITY: received real certificate (potential MITM or redirection)")`.

**Post-quantum key exchange.** The engine speaks the `X25519MLKEM768` hybrid group (curve 4588): the key share carries the ML-KEM-768 encapsulation key (1184 B) beside the X25519 public key; on a hybrid ServerHello the client decapsulates the server's 1088-byte ciphertext and feeds `pq || classical` to the TLS 1.3 key schedule. `SecP256r1MLKEM768` (4587) and `SecP384r1MLKEM1024` (4589) are parsed but rejected at handshake time, because the engine has no P-256 or P-384 ECDH; the rejection is an explicit error, not a silent classical fallback. REALITY accepts the 4588 share per xray `reality.go:79` and sing-box `reality_client.go:136`. ML-KEM-768 bytes come from RustCrypto `ml-kem`; the liboqs backend was removed on 2026-09-18 (cause, oracle and the unchanged FIPS 203 bytes are owned by [`crypto-dependencies.md`](crypto-dependencies.md)).

## Protocol support

Legend: `done` means implemented and verified; `in progress` means partial; `planned` means scheduled; `deferred` means planned but not scheduled; `no` means a decision not to implement; `blocked` means waiting on a prerequisite; `n/a` means the column does not apply.

The xray-core and sing-box columns describe the pinned reference trees under `thirdparty/`. "Native client" is the `leas-native` tunnel. "TLS engine" marks whether the protocol routes through `leas-tls`. "REALITY" marks REALITY compatibility. "e2e" is tier-3 proof.

### Overview matrix

| Protocol | xray-core | sing-box | Native client | TLS engine | REALITY | e2e |
|----------|:---------:|:--------:|:-------------:|:----------:|:-------:|:---:|
| VLESS | yes | yes | done | done | done | done |
| VMess | yes | yes | done | done | done | done |
| Trojan | yes | yes | done | done | done | done |
| Shadowsocks / Shadowsocks-2022 | yes | yes | done | done | done | done |
| SOCKS (client) | yes | yes | done | n/a | n/a | no (tier 1) |
| HTTP (client) | yes | yes | planned | n/a | n/a | planned |
| ShadowsocksR | no | yes | planned | n/a | n/a | planned |
| WireGuard | yes | yes | planned | n/a | n/a | planned |
| Hysteria2 | yes | yes | done | blocked (QUIC) | n/a | done |
| Hysteria1 | no | yes | planned | blocked (QUIC) | n/a | planned |
| TUIC | no | yes | planned | blocked (QUIC) | n/a | planned |
| Naive | no | yes | planned | done | n/a | planned |
| AnyTLS | no | yes | planned | done | n/a | planned |
| ShadowTLS | no | yes | planned | done | n/a | planned |
| Tor | no | yes | no | n/a | n/a | n/a |
| SSH | no | yes | planned | n/a | n/a | planned |
| Tailscale | no | yes | planned | n/a | n/a | planned |
| Redirect | no | yes | planned | n/a | n/a | planned |
| TProxy | no | yes | planned | n/a | n/a | planned |
| Mixed | no | yes | planned | n/a | n/a | planned |

Matrix notes:

- **TLS engine and REALITY columns** are `done` only for the TCP-stream family, where the security phase applies. QUIC-family protocols (Hysteria1/2, TUIC) carry TLS inside QUIC, so the engine's security phase never runs: `blocked`. That is orthogonal to the native column. Hysteria2 is native-complete because its quinn dial owns TLS internally.
- **SOCKS.** The client handshake is implemented in `crates/leas-native/src/protocol/socks/`: greeting, method, RFC 1929 auth, CONNECT, reply, every step under `timeouts::PROTOCOL`. An over-long credential is an error, never a panic. The client's UDP side is deliberately absent: SOCKS5 datagrams ride a raw UDP socket to the proxy, not the possibly TLS-wrapped `BoxStream` this layer sits on. The local SOCKS5 inbound serves TCP CONNECT and UDP ASSOCIATE, which is where UDP belongs. Coverage is tier 1 only: the client handshake has unit tests and the inbound has the relay bench, but there is no tier-3 row. The kind is also absent from `capability::NATIVE_KINDS`, so the TUI gate refuses the row as "no native implementation for this protocol kind" and keeps it on the subprocess; a direct `leas_native::connect` call reaches the client arm.
- **Shadowsocks** has no transport dimension: `SsConfig` carries no transport field, so the row is a plain TCP dial plus the `security` layer the chain applies outside the protocol. The accessor is `SsConfig::security()` in `crates/leas-proto/src/proto_spec/ss.rs`; while it was missing, the trait default (`None`) silently dropped a requested TLS layer and the handshake went out in the clear to a TLS listener.
- **Redirect, TProxy and Mixed** are outbound-only kinds: kernel or port forwarding with no client handshake of their own. The native `connect` is trivially a dial, but the `ConnectShape` path must exist first. The mixed *listener* is separate and implemented (`inbound/mixed.rs`).
- **Tor** is a full onion-routing stack (circuits, cell crypto, directory protocol). It stays out of the in-process core: a Tor profile remains visible and refuses connect with `support_reason`, never a hidden row or a silent fallback.
- **SSH, Tailscale and WireGuard** are device-tunnel or own-handshake shapes: divergent `connect()` paths, not the uniform pipeline.

### Per-protocol detail

**VLESS**: native implementation, `crates/leas-native/src/protocol/vless/`

| Capability | Detail |
|------------|--------|
| Encryption | None by default: identity is a UUID, with optional `xtls-rprx-vision` flow control. Account encryption `mlkem768x25519plus` is implemented: `mlkem768x25519plus.<native\|xorpub\|random>.<seconds>[s].<padding>`, the parser mirrors xray `infra/conf/vless.go`, ML-KEM-768 plus X25519 PFS wraps the session before the request header, and the sealed-record tunnel lives in `protocol/vless/encryption/`. The client always seals ChaCha20-Poly1305; the server may answer with either cipher. 0-RTT ticket resume is omitted. `encryption` composes with `flow`: vision sits on top of the sealed layer and its Direct handoff targets the encryption conn (`CanSpliceCopy = 3`, xray `proxy/vless/outbound/outbound.go:262-267`), so the outer TLS is never peeled |
| Auth | UUID, carried as the command bytes in the request header |
| Obfuscation | None at protocol level; REALITY supplies traffic camouflage |
| Transports | TCP, WS, gRPC, HTTPUpgrade, XHTTP (h1, h2, h3), h2 via the v2rayhttp transport, and mKCP. KCP is xray-only because sing-box has no kcp. Vision requires raw TCP: the Direct handoff needs the socket, so ws, grpc and xhttp framing are incompatible |
| UDP | `cmd 0x02` with `[2B BE len][payload]` datagram framing in both directions (`protocol/vless/udp.rs`), the `PacketConn` API with the shared response-header peel (`packet.rs`), and packetaddr mode (`packetaddr.rs`: the header destination is the magic fqdn `sp.packet-addr.v2fly.arpa`, and each frame carries `atyp\|addr\|port`, so no magic sits inside the frame). XUDP is implemented as UDP over the mux tunnel. Vision plus UDP is rejected on the raw path only, mirroring xray's UDP/443 rejection; UDP under a vision flow rides the mux tunnel |
| Flow | `xtls-rprx-vision` is implemented: padded camouflage frames, an inner-TLS filter and the Direct splice state machine (`protocol/vless/vision.rs`), with the flow addon in the protobuf request header. TCP transport only. A non-zero response version is a hard error, never payload. `xtls-rprx-vision-udp443`: the client config carries the full name (which selects the XUDP path, forcing mux and lifting the guard), the wire addon truncates to the first 16 bytes (`xtls-rprx-vision`, xray `requestAddons.Flow[:16]`), and the server validates against the truncated name |
| Mux | `cmd 0x03` v1.mux.cool multiplexer in `transport/mux.rs`, re-exported by `protocol/vless/mod.rs`: one tunnel with the fixed `v1.mux.cool:9527` header destination and no destination bytes on the wire, carrying concurrent TCP sessions and XUDP datagram sessions. `MuxClient` runs demux, writer and keepalive tasks with eager New, event-driven Keep/End, tunnel-level KeepAlive every 10 s and 8 KiB chunks. Vision plus mux peels the response header before the vision codec, mirroring xray `outbound.go` |
| Status | Native client complete, with e2e coverage listed under `## E2E coverage`. Deferred: HTTPUpgrade `ed` early-data, h2 PING keepalive, xmux (mux v2) and connection-reuse pooling, the browser-masquerade header set, and a general QUIC client transport for Hysteria1 and TUIC |

**VMess**: native implementation, `crates/leas-native/src/protocol/vmess/`

| Capability | Detail |
|------------|--------|
| Encryption | Payload `aes-128-gcm` and `chacha20-poly1305`. Legacy `aes-128-cfb` and `none` are not implemented (xray-only, and disabled in modern cores); `capability::vmess_reason` refuses them by name. A non-zero `alter_id` selects the legacy pre-AEAD session scheme, which the native client does dial (`protocol/vmess/legacy.rs`) |
| Auth | AEAD request header (mandatory), MD5 and HMAC-SHA256 KDF chain, FNV-1a and CRC-32 frame checks |
| Obfuscation | None at protocol level |
| Transports | TCP, WS, gRPC, HTTPUpgrade, XHTTP, h2, mKCP, and XHTTP-h3 through the shared dial |
| UDP | `cmd 0x02` AEAD-record datagram tunnel (`protocol/vmess/udp.rs`): each datagram is one AEAD record, written through the cancel-safe `VmessClientStream::write_datagram`, never the byte-stream `write_all`, whose dropped-future state would truncate the next datagram. There is no per-packet address: the header destination is the session target, so `send(None, ...)` is the normal call and a differing `Some(dest)` is refused as `InvalidInput`. Send payloads are capped at xray's chunk size (`8192 - 2 - 16`); reads accept the full u16 record |
| Status | Native client complete, with e2e coverage below. Deferred: HTTPUpgrade `ed` early-data, h2 PING keepalive, xmux and reuse pooling, the browser-masquerade header set, the v2rayhttp no-TLS h1 arm, and the general QUIC client transport |

**Trojan**: native implementation, `crates/leas-native/src/protocol/trojan/`

| Capability | Detail |
|------------|--------|
| Encryption | None: plaintext after TLS; the TLS layer is the security |
| Auth | `auth_key` (`protocol/trojan/mod.rs`): 56 lowercase hex characters of `sha224(password)`, mirroring xray `hexSha224` |
| Obfuscation | None; REALITY can carry it through the engine |
| Transports | TCP, WS, gRPC and HTTPUpgrade ride the uniform pipeline |
| Wire | Request `key(56) || CRLF || command(1) || ATYP+addr+port-BE2 || CRLF`, with the port last (trojan's `NewAddressParser` has no `PortFirst`, and sing-box's `SocksaddrSerializer` is port-last too). There is no server response header; both cores relay raw after the request |
| UDP | Command 3: per-datagram `ATYP\|addr\|port \|\| 2B len \|\| CRLF \|\| payload` (`connect_udp`), with the per-packet address defaulting to the session target. Send payloads are capped at 8192 (xray `maxLength`); reads follow the permissive peer and accept the full u16. A domain-addressed reply frame is delivered with no per-packet address instead of failing the session |
| Status | Complete, `{tcp, ws, grpc} × {standard, chrome-fingerprint} × both cores` plus the UDP row |

**Shadowsocks and Shadowsocks-2022**: native implementation, `crates/leas-native/src/protocol/ss/`

| Capability | Detail |
|------------|--------|
| Encryption | Classic 2017 AEAD: `aes-128-gcm`, `aes-192-gcm` (sing-box-only in the core whitelists), `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, with a fresh-salt HKDF-SHA1 subkey and two-seal chunk framing (`MAX_CHUNK = 0x3FFF`, `protocol/ss/stream.rs`). 2022-blake3: `2022-blake3-aes-128-gcm`, `-aes-256-gcm`, `-chacha20-poly1305`, with a BLAKE3 `derive_key("shadowsocks 2022 session subkey", psk \|\| salt)` truncated to the method's key length and standalone header chunks (`protocol/ss/stream2022.rs`). The legacy stream set is also native (`protocol/ss/stream_legacy.rs`): `aes-{128,192,256}-cfb`, `aes-{128,192,256}-ctr`, `rc4-md5`, `chacha20-ietf`, `xchacha20` and `none`, one continuous keystream per direction behind an IV, no chunk framing, with the algorithms in `crypto/legacy_stream.rs` (`aes-{128,192,256}-ctr` and `chacha20-ietf` compose the `ctr` and `chacha20` crates rather than re-implementing them; `rc4-md5` keys RC4 with `MD5(master \|\| IV)`) |
| Auth | None beyond the AEAD key. Classic uses MD5 `EVP_BytesToKey`; 2022 uses the PSK, whose shape rule is xray's `ParseKey` (`proto_spec::ss2022_key`): standard base64, else the literal bytes, and in both cases exactly the method's key length. A `:`-separated multi-user PSK list is a valid config that only the subprocess serves; 2022 multi-user EIH is not implemented and there is no proto identity field. An unusable key is dropped at import (`validate_ss_config`). `none` is admitted only when a TLS-bearing layer wraps it; a cleartext `none` row is dropped at import |
| Obfuscation | SIP003 plugins are served natively (simple-obfs `obfs=http` and `obfs=tls`, v2ray-plugin `mode=websocket`) with framing in `transport/v2ray/` and mux as the protocol phase in `protocol/ss/mux.rs`. `tls` is presence-only: every value, including `tls=0`, means TLS on, because both references read the key and never the value. `cert` and `certRaw` are honoured as a per-row SPKI pin, where v2ray-core appends the cert to the system roots; a mismatch yields `[cert]`. `mode=quic` rows are rejected at import: the peer speaks QUIC draft-29/32/34 (v2ray-plugin v1.3.2 embeds v2ray-core 4.38.3 and quic-go 0.20.1) and every QUIC stack here speaks RFC 9000 v1 |
| Transports | TCP only. `SsConfig` carries no transport field, so the row is the plain dial plus the optional `security` layer from `SsConfig::security()` |
| Wire (classic) | `[salt][ [2B BE len][16B tag][ct][16B tag] ]*` per direction: two AEAD seals per chunk (length, then payload) under consecutive counter nonces, independent salt, subkey and counter per direction, `len <= 0x3FFF`. A zero-length chunk is refused (mihomo `ErrZeroChunk`). The first payload is the target address in SOCKS5 port-last form (`addr::encode_addr_port_last`), not the VLESS/VMess port-first form |
| Wire (2022) | Request `[salt][seal(11B: type=0, ts u64be, len u16be)][seal(addr, pad_len u16be, padding, payload)][seal(2B len)][seal(payload)]...`; response `[salt][seal(27 or 43B: type=1, ts u64be, request_salt, len u16be)][seal(payload)][seal(2B len)][seal(payload)]...`. The little-endian counter advances on every seal and open, so the reader keeps one half-state across the response header and the chunks after it. Three client rules break interop silently: the response `request_salt` must equal the salt this client sent, salt plus both request header chunks leave in one write, and a request with no initial payload always pads; this client never sends one |
| UDP | A dial-end carrier for both families (`protocol/ss/udp.rs`, `PacketTunnel::Ss`): `connect_udp` binds its own `UdpSocket` to the server's port, so a datagram carries no in-tunnel framing, and `chain.rs::ss_udp_guard` refuses any chain around it, as does a non-empty `security` on the UDP path. Classic uses a fresh salt and subkey per datagram with the address always on the wire. 2022 AES methods seal the body under the plaintext separate header's `[4..16]` nonce; ChaCha prepends a 24-byte nonce and seals `[client_session_id, packet_id, body]` with the PSK. The session table holds one current and one previous server session (spec §3.2.4) with a 1024-id replay window anchored at the highest committed id, a ±30 s timestamp gate and a 60 s rotation quiet period |
| Status | Complete. 21 e2e cases expand to 31 entries (see `## E2E coverage`). Deferred: 2022 multi-user EIH only. `mode=quic` is refused at import for the wire-version reason above |

**Hysteria2**: native implementation, `crates/leas-native/src/protocol/hysteria2/`

| Capability | Detail |
|------------|--------|
| Encryption | TLS 1.3 inside QUIC via quinn and rustls, ALPN `h3`, `insecure` honoured, webpki-roots by default with a harness-CA override in test builds. QUIC TLS is internal, so no fingerprint row exists |
| Auth | HTTP/3 POST `https://hysteria/auth` with the `hysteria-auth` header; status 233 means OK (`runtime_auth`) |
| Obfuscation | `salamander` obfs (`crypto/salamander.rs`): an 8-byte random salt and a payload XOR with `blake2b-256(psk \|\| salt)`, applied through a `quinn::AsyncUdpSocket` wrapper that transforms every QUIC datagram |
| Transports | QUIC. The fresh quinn dial replaces dial, security and upgrade (`ConnectShape::Quic`; `protocol/hysteria2/quic.rs` uses the shared `transport/quic.rs` helpers). The TCP tunnel is a raw quinn bidi stream carrying a `TCPRequest` frame (`varint 0x401, addrLen, addr, padLen, padding`) and a `TCPResponse` (status 0 means OK), then the `H2Stream` relay. The h3 session must outlive the tunnel: the server runs the h3 `StreamDispatcher` over the same quinn connection, so dropping the last `SendRequest` clone after auth tears the connection down; the `H3Keepalive` guard in `H2Stream` holds it |
| UDP | QUIC DATAGRAM relay (`protocol/hysteria2/udp.rs`, `UdpConn`), gated by the auth response's `Hysteria-UDP` header. Each datagram is a `UDPMessage` (`sessionID u32 BE, packetID u16 BE, fragID u8, fragCount u8, addrLen varint, addr, payload`), with fragmentation on `DatagramTooLarge` and per-session defrag. `send(None, ...)` carries the session destination, since every `UDPMessage` has an address on the wire. An undeliverable datagram (foreign session, malformed, incomplete fragment) is dropped and the loop keeps reading, as upstream does. The client sends its maximum receive bandwidth in the `hysteria-cc-rx` auth header, derived from the config `down` string |
| Status | Complete: sing-box is the only server core (xray-core has no Hysteria2 inbound). E2E covers default cert-TLS, salamander-obfs and the UDP row |

**Remaining kinds**

| Kind | Shape | Status |
|------|-------|--------|
| HTTP client | Uniform pipeline over TCP | planned: `protocol/http/mod.rs` is a placeholder; the HTTP *inbound* is implemented |
| ShadowsocksR | Uniform pipeline plus obfs and auth plugins | planned: sing-box only; the plugin matrix is the bulk |
| WireGuard | Device tunnel | planned: needs a TUN or userspace device abstraction; `ConnectShape` is divergent |
| Hysteria1 | QUIC dial | planned: sing-box only; blocked on a general QUIC client transport |
| TUIC | QUIC dial | planned: sing-box only; blocked on the same |
| Naive | HTTP/2 CONNECT with Chromium semantics | planned: the TLS engine is ready; needs a full HTTP/2 client (the current `http2/` layer is grader-minimal) |
| AnyTLS | Uniform pipeline over TLS | planned: the TLS engine is ready |
| ShadowTLS | Uniform pipeline over TLS | planned: the TLS engine is ready |
| SSH | Own handshake | planned: `ConnectShape::HandshakeOwn` |
| Tailscale | Device tunnel plus DERP | planned: needs the coordination protocol |
| Tor | Own handshake | no: a full onion-routing stack stays out of the in-process core |
| Redirect, TProxy, Mixed | Outbound-only kinds | planned: `PlaceholderConfig` in proto; the native arm returns `NotImplemented` |

## Transport support

| Transport | Status | Notes |
|-----------|:------:|-------|
| TCP | done | `transport/tcp.rs`; the default dial for every TCP-stream e2e case |
| WS | done | `transport/ws.rs`: tokio-tungstenite framing over the engine stream, v2ray Host, path and headers. `?ed=N` early data defers the upgrade to the first protocol write so those bytes ride `Sec-WebSocket-Protocol` (`EarlyDataDial`). E2E against xray and sing-box, standard and chrome fingerprint |
| gRPC | done | `transport/grpc.rs`: h2 framing over the engine stream in gun mode, with the `Hunk` protobuf (`0x0A` plus varint) inside the 5-byte gRPC prefix. E2E against both cores |
| HTTPUpgrade | done | `transport/httpupgrade.rs`: hyper http1 connection plus an RFC 7230 101 upgrade over the engine stream, with the `Connection: Upgrade` and `Upgrade: websocket` echo validated, ALPN `http/1.1`. E2E against both cores |
| XHTTP (splithttp) | done | `transport/xhttp.rs`, v3 dialect, xray-only server: a UUID session in the path, GET-body download, raw POST uploads (sequence, 30 ms pacing, `Referer` `x_padding` over an 8-bit Huffman alphabet in `[100, 1000)`, and a random per-POST size up to `scMaxEachPostBytes`). No 500 ms camouflage timer is implemented; padding rides the request head. Modes packet-up, stream-up and stream-one. Transport selection mirrors xray `decideHTTPVersion`: reality selects h2, no TLS selects h1.1, a single `h3` ALPN selects QUIC, zero or two-plus ALPNs select h2. The auto rule: `""` or `auto` selects packet-up, a reality config selects stream-one, reality plus download settings selects stream-up. The h3 dial replaces dial, security and upgrade (`connect_quic`, quinn and rustls internal, webpki-roots default with the harness CA as trust anchor) |
| h2 (v2rayhttp) | done | `transport/v2rayhttp.rs`: one h2 full-duplex PUT stream, `:authority` from the config host else `www.example.com`. sing-box only; xray removed the h2 transport in 26.x |
| QUIC (bare transport) | in progress | quinn and h3 landed as the xhttp h3 dial and the Hysteria2 client dial. `TransportConfig::Quic` itself returns `NotImplemented("transport quic")`, and a general QUIC client transport for Hysteria1 and TUIC remains blocked |
| KCP (mKCP) | done | `transport/kcp/`: xray's KCP fork over UDP with wire codec, session (windows, retransmit, RTO, congestion) and stream. One segment per datagram; conv from a process-global counter. `KcpSettings::with_capacities` reads `mtu` (default 1350), `tti` (default 50) and the `uplink_capacity`/`downlink_capacity` knobs (default 5 and 20) into the send and receive inflight sizes. `mask.rs` implements xray's `finalmask` datagram masks: `header-srtp`, `utp`, `wechat` (also spelled `wechat-video`), `dtls`, `wireguard`, `dns`, the FNV `mkcp-original` cascade, and the `mkcp-aes128gcm` seed envelope; the wire is `envelope(prefix ‖ payload)` with per-connection counters. Vectors came from the pinned core's own `finalmask` packages, and tier-3 runs 5 mask rows against xray 26.3.27. xray-only: sing-box has no kcp |
| obfs plugins (SS) | done | SIP003 rows are served natively (simple-obfs and v2ray-plugin), with the typed model in `proto_spec/ss_plugin.rs` (`PluginSpec`, `PluginFamily`, `PluginMode`, `TlsSetting`, `MuxSetting`, plus an `Invalid(String)` arm so an unsupported spelling is stored, never rewritten to a default). Framing lives in `transport/v2ray/http_obfs.rs`, `tls_obfs.rs` and `ws.rs`. simple-obfs TLS is not a TLS handshake: it is a synthetic record writer whose layouts are pinned against real `sizeof` and `offsetof` (server hello 96 B, change-cipher-spec 6 B, encrypted handshake header 5 B, first payload length at offset 105, payload at 107, all packed and aligned to 1). TLS stays outermost for WebSocket. Mux is the protocol phase (`protocol/ss/mux.rs`): each session takes its own salt, subkey and counter stream, targeting `v1.mux.cool:9527`, and `MuxTunnel` is deliberately not `Clone` so a session id is never duplicated. UDP is refused per association with one warning |
| | | `mode=quic` is refused and new rows are rejected at import: the peer speaks QUIC draft-29/32/34 (v2ray-plugin v1.3.2 embeds v2ray-core 4.38.3, which pins quic-go 0.20.1 with `SupportedVersions = {draft29, draft34, draft32}`) while every QUIC stack here speaks v1. The sources are vendored under `thirdparty/`, so this is an implementation-surface verdict, not an evidence gap. Already-stored rows keep the named marker; without it a row would open a TCP connection to a server answering on UDP/443 |

Two transports are refused at config-build time for xray-core: `validate_xray_transport` (`crates/leas-proto/src/proto_spec/common.rs`) rejects `TransportConfig::Http` and `TransportConfig::Quic` with `SupportError::Config`, called from the three `inject_xray` arms that emit a variable transport (vless, vmess, trojan). xray-core 26 removed both (`PrintRemovedFeatureError` returns an error, not a warning), so an emitted config would be refused by the core. The native engine serves the h2 transport (v2rayhttp), and serves QUIC only through the xhttp h3 dial, not as the bare `quic` transport; `resolve_runtime_core` sends every native-capable kind to native before any build, so the refusal is reachable only through an explicit xray override, and the connect path then warns `protocol_core_overrides asked for the native core: override NOT honored` (`crates/leas/src/ops/connect.rs`).

Transport deferrals, documented with no stub:

- **General QUIC client transport**: the quinn and h3 stack serves the xhttp h3 dial and the Hysteria2 dial; a general transport gating Hysteria1 and TUIC is still deferred.
- **HTTPUpgrade `ed` early-data**: an xray-only client flag; the server sees a normal 101 exchange.
- **h2 PING keepalive**: `idle_timeout` and `ping_timeout` in `HttpConfig` are not wired.
- **xmux (mux v2) and connection-reuse pooling**: the classic v1.mux.cool multiplexer is implemented; xray's newer dialect and cross-tunnel reuse remain deferred.
- **Browser-masquerade default header set**: servers validate Host, path and padding only. Functional correctness first; masquerade is later DPI polish.
- **v2rayhttp no-TLS h1 arm**: sing-box hijacks raw bytes with no Content-Length, while hyper always frames request bodies, so chunked bytes would pollute the hijacked stream. Real-world use is TLS.

## E2E coverage

The suite runs the native client against xray-core 26.3.27 and sing-box 1.13.16 (both pinned and version-asserted). Every both-core case expands to two tests, one per core. Counts below were verified against the test sources on 2026-11-06.

**VLESS and VMess transport matrix** (`tests/vless.rs`, `tests/vmess.rs`): 150 test functions, 143 green and 7 ignored. VLESS contributes 97 (90 green, 7 ignored) and VMess 53 (all green). The ignored VLESS rows are the four ws and grpc plain-into-reality-server semantic rows (the destination sees ws or grpc framing, not HTTP, so the transport is unreachable before the proxy), the reality-pq row (the harness destination has no PQ), and the two environment-gated HEAD and reference-pair differentials. Single-core rows run only on the serving core: xhttp, xhttp-h3, kcp and pq-enc on xray; v2rayhttp, ws and httpupgrade reality, mux-vision and vision-udp443 on sing-box. The cases cover TCP, WS, gRPC, HTTPUpgrade, XHTTP, h2, KCP and XHTTP-h3.

**TLS-variant set**, each row run against both cores with a real server inbound and the native client dialing it:

| Case | Payload security | TLS variant |
|------|------------------|-------------|
| VLESS | none | tls-standard |
| VLESS | none | tls-chrome (fingerprint engine) |
| VLESS | none | reality |
| VLESS | none | reality-wrong-pbk (client holds a wrong pbk, the server proxies, Spider-X and fallback follow) |
| VLESS | none | reality-wrong-sid (client sid mismatch, the server proxies, Spider-X and fallback follow) |
| VLESS | none | reality-server-plain-client (a plain fingerprint probe through a REALITY server is transparently proxied to the destination) |
| VLESS | none | plain-server-reality-client (a REALITY client against a cert-TLS server, then Spider-X and fallback) |
| VMess | aes-128-gcm | tls-standard |
| VMess | chacha20-poly1305 | tls-standard |
| VMess | aes-128-gcm | tls-firefox (fingerprint engine) |
| VMess | aes-128-gcm | reality |

The two-server scenarios are `reality-wrong-pbk`, `reality-wrong-sid` and `reality-server-plain-client`: the REALITY server's `dest` is a second local server (`tls_echo`), so a fallback or a transparently proxied plain probe terminates there and the recording server observes the client's bytes (spider h2 preface or plain-TLS ClientHello). `plain-server-reality-client` is a single-server scenario: the fallback terminates at the plain TLS server itself, so the spider's bytes never reach a destination (`spider_reaches_dest()` is false). The two fallback cases, `reality-wrong-pbk` and `reality-wrong-sid`, expect `connect()` to fail with the fallback error and skip the probe; every other row probes HTTP through an established tunnel.

**Trojan axis** (`tests/trojan.rs`): 7 case rows, 14 tests. The TCP-stream trojan (password header plus raw relay) crosses network `{tcp, ws, grpc}` with TLS `{standard, chrome fingerprint}`, plus the UDP row, each on both cores.

**Hysteria2 axis** (`tests/hysteria2.rs`): 3 rows against a sing-box hysteria2 inbound (xray-core has no Hysteria2 server): default cert-TLS, salamander obfs, and the QUIC DATAGRAM UDP relay (UDPMessage framing plus fragmentation). QUIC TLS is rustls-internal, so no fingerprint row exists.

**Shadowsocks axis** (`tests/shadowsocks.rs`): 21 cases expanding to 31 entries. Ten dual-core rows (20 entries) cover the classic AEAD set, the three 2022 methods including the 16-byte key length that proves the BLAKE3 XOF truncation, and four UDP rows including the 2022 ChaCha20-Poly1305 merged-id shape. One xray-only row adds cert TLS through the engine with the chrome fingerprint; sing-box 1.13.16's shadowsocks inbound has no `tls` field at all (`option/shadowsocks.go` embeds only `ListenOptions`, so the config decode is fatal), and `with_single_core` reports the excluded combination instead of counting it green. Ten sing-box-only rows cover the legacy stream methods (seven TCP methods plus `none`) and two legacy UDP methods; xray's roster has no legacy entry. The relay needs the server to enable UDP: xray serves it only when its inbound sets `network: "tcp,udp"` (`proxy/shadowsocks/server.go:81-87`, `infra/conf/common.go:110-112`), sing-box serves both by default. An xray SS inbound without it serves no UDP relay to any client, the subprocess path included, so this is an operator caveat rather than a native-versus-subprocess difference; the native client matches xray's (`proxy/shadowsocks/client.go:59-67`, `UDPWriter` at `:156-181`). Hermetic cost proof: `benches/ss_codec.rs` measures 22 rows (classic TCP chunk seal and open per cipher, the two 2022 TCP chunk rows, `kdf/hkdf_sha1` and `kdf/blake3`, and the classic and 2022 UDP paths) via `cargo criterion -p leas-native --bench ss_codec`; `benches/throughput.rs` adds four rows (`ss/tcp/aead-aes-128-gcm`, `ss/tcp/aead-chacha20-ietf-poly1305`, `ss/tcp/2022-blake3-aes-256-gcm` on xray, `ss/tcp/2022-blake3-chacha20-poly1305` on sing-box).

**VLESS vision flow axis** (spec §7.4): 8 tests from 4 both-core rows. `flow = xtls-rprx-vision` with the tcp network crosses `{xray, sing-box}` with outer `{tls, reality}` and app `{plain, inner-tls}`. The inner-tls rows drive the Direct-splice path: the app establishes a real TLS 1.3 session through the tunnel to the rustls echo target, then the vision filter switches both directions to a raw relay after the Direct frame. The plain rows exercise the End path, where padding stops and outer TLS continues. UDP under these flows is rejected on the raw path only; it rides the mux tunnel instead.

**VLESS UDP path** (spec §4): 4 both-core tests for `cmd 0x02` Raw mode over `{tls-standard, reality}`; one sing-box test for packetaddr over tls, because xray-core's VLESS has no packetaddr registration. The framing is `[2B BE len][payload]` in both directions over the tunnel stream (`protocol/vless/udp.rs`), with the `PacketConn` API and the shared response-header peel (`packet.rs`).

**VLESS mux axis** (spec §5): 4 both-core tests for `{tls, reality}`, each tunnel carrying 4 concurrent sessions to the echo target with every response asserted, plus one sing-box row for vision plus mux. xray-core rejects vision plus mux TCP by server design (its vision-plus-mux path is the XUDP route, `AllowedNetwork = UDP`), so the vision row is sing-box only.

**VLESS XUDP axis** (spec §7.3): 3 case rows, 6 tests. One `cmd 0x03` tunnel plus one UDP session (`UdpSession`, `open_udp_session`) carries a fresh random 8-byte `GlobalID` per tunnel, written on the New frame only (xray `frame.go` `WriteTo`); each datagram is a `Keep` frame with its own per-packet destination, wrapped in the `PacketMode::XUdp` `PacketConn`. Echoes are matched by payload, order-independent. Both cores serve `{tls, reality}` plain XUDP and the `xtls-rprx-vision-udp443` flow; the client carries the full flow name, the wire addon truncates to `xtls-rprx-vision`, and the server config emits the truncated name (`Flow::server_str`). The xray arm was verified in the final-review fix wave.

**VLESS mKCP axis** (spec §7.3): 7 xray-only rows. Two are composition rows: `kcp_plain`, the suite's genuinely no-TLS row (server `streamSettings` without `tlsSettings`, client security none), and `kcp_chrome` (tls with the chrome fingerprint engine). Five are mask rows: `kcp_mask_srtp`, `kcp_mask_dns`, `kcp_mask_seed`, `kcp_mask_srtp_seed` and `kcp_mask_wechat_seed`, which pin the camouflage header prefix and the AES-128-GCM seed envelope against xray 26.3.27's own `finalmask` implementation. The kcp+reality arm is dropped (spec deviation 5): xray-core 26.3.27's `StreamConfig.Build()` rejects `security: "reality"` over any protocol but tcp, splithttp and grpc, with "REALITY only supports RAW, XHTTP and gRPC for now", so no core can serve reality over kcp. The native client's reality-over-kcp dial stays implemented, unreachable server-side exactly like xray's own client.

**VLESS ML-KEM PQ axis** (SP7, spec §7.3): 3 VLESS rows plus 1 VMess row. `tcp_tls_pq` runs on both cores (sing-box 1.13.16 accepts `curve_preferences`, verified empirically; the spec's "sing-box 1.18+" note is stale) with the hybrid curve pinned on both ends, so a green row is a negotiated ML-KEM-768 exchange and never a classical fallback; the runner also asserts the engine's `negotiated_hybrid()` flag, set from the ServerHello ML-KEM ciphertext. `tcp_reality_pq` is ignored, blocked by the harness destination rather than the client: xray REALITY replays the destination's ServerHello flight as camouflage (`xtls/reality tls.go` `s2cSaved`, group check at `:359`) and the rustls `tls_echo` destination has no PQ, so the tunnel is structurally classical whatever the client offers. The client's REALITY 4588 support is proven hermetically instead, by a fake REALITY PQ server with real encapsulation, an HMAC-stamped Ed25519 certificate and an encrypted echo. `tcp_pq_enc` is green since 2026-09-23: the VLESS `mlkem768x25519plus` account encryption end to end, with the client outbound `encryption` carrying the server's public halves (X25519 public key and ML-KEM encapsulation key) and the xray inbound `settings.decryption` the private halves, bridged by `keypair_from_seed` (FIPS 203 `d || z`). It had been ignored for a long stretch as an "unresolved interop divergence"; the PQ wire was in fact byte-correct the whole time (the server decoded the request, `firstLen = 26`, and dialed the echo on every attempt while the client received the full `200 OK` body). The defect was the record layer's EOF classification: `CommonConn::poll_read` raised `UnexpectedEof` on a clean end of stream at a record or padding-field boundary, so the probe's `read_to_end` discarded an already complete response and reported `status 0 body ""`. Go's `io.ReadFull` (xray's framing) yields bare `io.EOF` when zero bytes were read into a field and `ErrUnexpectedEOF` only mid-field, and the reader now mirrors that, pinned by the hermetic `eof_at_a_record_boundary_is_clean`. The capability gate no longer defers this shape; `mlkem_encryption_supported` accepts every value the connect-path parser accepts, so Auto resolution now picks the in-process core for a PQ account. pq-enc is xray-single-core because sing-box has no VLESS account encryption. The VMess `tcp_aes128gcm_tls_pq` row mirrors `tcp_tls_pq` on both cores.

**VLESS XHTTP/3 axis** (spec §7.3): 1 row, xray single-core, since sing-box has no xhttp-over-QUIC. A single exactly-one `h3` ALPN flips the xray splithttp listener to QUIC and HTTP/3 (`hub.go` `isH3`), and the client's `connect_quic` (quinn endpoint over UDP, ALPN `h3`) runs the splithttp v3 protocol over HTTP/3. The v3 session, GET and POST logic is shared with the h1 and h2 arms through the `V3Send` seam, with h3 requests in absolute-URI form (`:scheme` and `:authority`, RFC 9114 §4.3.1, the interop fix). Reality is impossible here (`decideHTTPVersion` returns h2 when a reality config is present), h3 requires TLS, and the engine TLS is not involved in QUIC, so the row is tls-standard.

**Second pinned peer for differentials (2026-09-22).** `XRAY_HEAD_VERSION` (26.7.28) plus `LEAS_CORE_HEAD_BIN_DIR`, resolved through `CoreUnderTest::resolve_from`, give the suite a second xray peer while `XRAY_VERSION` (26.3.27) stays the baseline so its rows are not re-baselined. First use: `vless_pq_enc_against_head` ran the pq-enc case against HEAD and found it behaved identically to the baseline (connect Ok, probe reads nothing, no server-side error at either). That ruled out a version delta, but the "the client's wire is wrong" reading drawn from it was wrong: the wire was byte-correct and the shared symptom was the record layer turning a clean EOF into an error. Both differentials now pass.

**Plugin evidence.** `tests/plugin_sip003.rs` covers rows 1, 2, 3, 4, 4b, 5 and 15 against a real v2ray-plugin and simple-obfs server, opt-in via `just plugin-bins`. `tests/plugin_3a.rs` is the structural differential against sing-box's in-process plugin client: normalized WS head, mux New/TCP/domain class and summed `data_len`, with the random WS key and the target port and session id masked. Raw-byte equality is not the claim; the three fields that differ are the ones that must differ.

**Probe writes ranking inputs.** A successful real probe through the native tunnel is the "newest real probe succeeded" fact that materialises the `Alive` band (band 0) of the endpoint ranking. The ranking law itself is owned by [`ordering-law.md`](ordering-law.md); the probe's two-budget measurement is described under the crate map.

## Where this is headed

1. **Finish the TCP-stream protocol family** (HTTP, AnyTLS, ShadowTLS, Naive): the TLS engine is done and the shapes are uniform. The SOCKS client and inbound, Trojan and both Shadowsocks kinds are complete.
2. **Non-TCP transports**: the TCP-stream transport set is done (WS, gRPC, HTTPUpgrade, XHTTP, h2) and mKCP landed. The quinn stack serves the xhttp h3 and Hysteria2 dials; a general QUIC client transport unlocks Hysteria1 and TUIC.
3. **TUI wiring** is done (2026-09-03, [`../architecture/native-core-integration.md`](../architecture/native-core-integration.md)): no per-profile toggle and nothing native persisted. The connect-time gate prefers the in-process core for the six e2e-verified protocol kinds (vless, vmess, trojan, hysteria2, shadowsocks, shadowsocks-2022) via `capability::supported`, with a loud downgrade to xray-core for deferred configs. `NativeCoreServer` (one mixed SOCKS5 and HTTP CONNECT inbound, proxy-all engine, watch shutdown) runs from `ops/native_connect.rs`; `ops/connect.rs` keeps the subprocess arm as the downgrade, with a loud reason line. Telemetry feeds the existing stats and logs screens plus the Native Activity tab.
4. **Routing and outbound-only kinds** via native: the SOCKS5 inbound is done; the remaining piece is the outbound-only redirect dial for split-tunnel rules.
5. **TLS 1.2 CBC and static-RSA suites**: the engine's TLS 1.2 path is ECDHE plus AEAD only, so servers that require CBC encryption or RSA key exchange remain unreachable.
