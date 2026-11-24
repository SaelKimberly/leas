# Ferrox vs leas: implemented protocols, functional gaps, memory efficiency

Read of [`thirdparty/ferrox`](../../thirdparty/ferrox) (clone of `github.com/ferroxdev/ferrox`, `main`, 2026-11-23) against this tree. It is a core-and-server rewrite; leas is a native-only client with a persistent profile store and a TUI. The shared surface is the client-side protocol engine, and that is where parity and the gaps below are judged. Server-role claims are recorded only where they explain a capability difference.

Not authoritative. Every claim names the file or page it was read from; nothing here was benchmarked on this machine.

## 1. Category difference

| | leas | ferrox |
|---|---|---|
| Product | Desktop client: TUI, DB (turso), subscriptions, import/export, per-link probing, routing, telemetry | From-scratch proxy core + xray-compatible CLI/app; both roles, TUN, server features |
| Production engine | In-process native core only. The subprocess xray/sing-box path survives only in `leas-oracles` | Its own engine; xray-core is the drop-in compatibility target |
| Roles | Client outbound; local SOCKS5/HTTP/mixed inbounds | Client and server for almost every protocol; TUN/transparent inbounds |
| Verification | Hermetic unit/golden tests + real-core e2e against pinned xray/sing-box/mihomo (`leas-oracles`) | Bit-identical differential against pinned references, Miri, exact operation/allocation/syscall counts, 239-cell benchmark matrix |

Ferrox's licence is `MIT OR Apache-2.0`; leas reads it as a reference tree, no code imported.

## 2. Protocol and transport coverage

Legend: **yes** = implemented; **client** = leas serves it as a client only (the product has no server role); **partial** = implemented subset; **no** = not dialable in production; **placeholder** = a module exists but returns `NotImplemented`.

leas coverage is judged by production dial dispatch (`capability::support_reason` plus the native module's `connect`/`connect_udp` arm), not by the `protocols.md` build columns: those columns describe the dev-only subprocess builders in `leas-oracles` and would overstate what ships. On the ferrox side, "implemented" was taken from its method pages and the `ferrox-app` dispatch arm, not from a file name.

### 2.1 Proxy protocols

| Protocol | Ferrox | leas native | Consequence |
|---|---|---|---|
| VLESS TCP none/TLS/REALITY | yes, both roles, all carriers | client | Client parity. Both do Vision, ML-KEM `mlkem768x25519plus`, XUDP/Mux.Cool |
| VLESS `xtls-rprx-vision-udp443` | yes, outbound | client | Parity |
| VMess (AEAD + legacy) | yes, both roles, UDP on every carrier | client, AEAD + legacy (`protocol/vmess/legacy.rs`), UDP | Parity on framing. Ferrox serves it; leas dials it |
| Trojan | yes, both roles, TCP+UDP, REALITY on TCP, mux | client, TCP+UDP | Parity |
| Trojan-Go `ss;<method>` layer | not carried | client (`protocol/trojan`, ADR 0018) | leas accepts a row ferrox does not |
| Shadowsocks AEAD + `rc4-md5` | yes, both roles, all carriers | client | Parity |
| Shadowsocks-2022 | yes, both roles, EIH multi-user, relay | client | Parity on client |
| Shadowsocks legacy stream set | refuses `aes-192-gcm`, `none`, CTR/CFB/chacha20-ietf/xchacha20 as broken/deprecated (`docs/function/shadowsocks.md`) | implements the sing-box legacy roster (`NATIVE_SS_METHODS`, 23 names) | leas dials more legacy rows; ferrox is deliberately narrower |
| AnyTLS v2 | yes, both roles, 8 idle sessions, no UoT | client, TLS multiplexing, padding, **UoT v2** | leas has the UDP lane ferrox excludes |
| TUIC v5 | yes, both roles, 0-RTT, QUIC UDP relay | `protocol/tuic/` placeholder | **leas gap** |
| Hysteria2 | yes, both roles, salamander/gecko, masquerade, port-hop | client (QUIC, salamander) | Client parity minus port-hop/masquerade options |
| Hysteria v1 | yes (standalone and as a carrier) | placeholder | **leas gap** |
| WireGuard / WARP | partial: userspace smoltcp, both roles, no cookie reply; WARP + nested WireGuard (gool/classic/mim) | placeholder | **leas gap** |
| MASQUE CONNECT-IP / CONNECT-UDP | yes, both roles, h1/h2/h2c/h3 | none | **leas gap** |
| ShadowTLS / SSH / Naive / Tor / Tailscale / Snell / OpenVPN / AmneziaWG / SSR | planned, except SSH/OSSH inside the Psiphon lane | placeholders | Both open; ferrox has the SSH wire inside one carrier |
| SOCKS5 client | yes, CONNECT + UDP ASSOCIATE; SOCKS4/4a both roles | client CONNECT; SOCKS5 inbound with UDP ASSOCIATE; SOCKS4 absent | Client CONNECT parity; leas lacks SOCKS4/4a |
| HTTP proxy | yes, both roles, CONNECT + origin-form | inbound only; `protocol/http/` is a placeholder outbound | **leas gap** for HTTP proxy as an upstream |
| dokodemo / TUN / transparent / reverse / blackhole / DNS-outbound / freedom / loopback | yes | only direct/block outbound kinds and SOCKS/HTTP/mixed inbounds | Engine-scope gap; mostly irrelevant to a client |

### 2.2 Transports and carriers

| Transport | Ferrox | leas native |
|---|---|---|
| raw TCP | yes | yes |
| WebSocket | yes (early data both roles) | yes |
| HTTPUpgrade | yes (`?ed=` both roles) | yes |
| gRPC | yes, full HTTP/2 + HPACK + status trailers | yes (`transport/grpc.rs`) |
| h2 `type: http` (sing-box v2rayhttp) | planned (`carrier-v2ray-http`) | **yes** (`transport/v2rayhttp.rs`) |
| TCP HTTP-header masquerade (`tcpSettings.header.type=http`) | yes | **no** |
| xHTTP h1/h2c/h3, all modes | yes, `xmux` pool for REALITY/TLS stream-one | yes, three modes, h3 with single `h3` ALPN, xmux-style h2 pool (`transport/xhttp.rs`) |
| QUIC transport (`vless-quic`, `vmess-quic`, `trojan-quic`) | yes, 0-RTT, migration, pooled handshakes | **no**: `TransportConfig::Quic` is parsed but `transport::connect` refuses it; QUIC exists only for xhttp h3 and Hysteria2 |
| mKCP | yes, both roles, masks | yes, client |
| Hysteria as a carrier for VLESS/Trojan | yes | **no** |
| xdrive (Drive/S3/template carrier) | yes | **no** |
| Foxy / VeePN / Psiphon / browser dialer | yes | **no** |
| Unix domain socket | yes | **no** |
| SIP003 plugin (`v2ray-plugin`, `obfs-local`) | planned | **yes**, native framing + oracle rows (`transport/v2ray/`) |
| Mux.Cool / XUDP | yes | yes, pooled carriers (`mux_pool.rs`) |
| smux / yamux / h2mux | yes, both roles | yes, hand-written for sing-box carriers (`transport/sbox/`); mihomo h2mux fork is an ignored interop row |
| TLS 1.2 fallback | partial: cipher ids parsed, rustls lane has no TLS 1.2 (`security-tls-options`) | yes: ECDHE X25519/P-256 + AES-GCM/ChaCha20-Poly1305 (`leas-tls/src/handshake/tls12.rs`) |
| uTLS-style fingerprints | 50 names onto 31 presets, oracle-replayed | 71 JA4-faithful profiles (2 hand + 69 generated), id without a row is approximated and marked |
| ECH | yes, client + server, HPKE | yes, client only (RFC 9849 subset: X25519/HKDF-SHA256/AES-128-GCM) |
| REALITY | server complete; client per README row 39 | client, any resolvable fingerprint, X25519MLKEM768 share, Spider-X |
| kTLS | yes (Linux, both roles) | no |
| TLS session resumption | bounded cache only on its BoringSSL lane; shaped hello keeps no ticket | none: `NewSessionTicket` consumed and discarded |

Counts: ferrox's method ledger has 116 rows, of which 63 are implemented and 7 partial (`docs/method-superset.md`). leas's native roster is 7 protocol kinds plus SOCKS5; every other kind in `ProtocolKind` is a placeholder and, with production native-only, is **not connectable**.

## 3. Functional gaps that matter to a leas user

1. **TUIC v5, WireGuard/WARP, Hysteria v1, ShadowTLS, Naive, SSH, Tor, Tailscale, SSR** — ferrox implements or is actively building these; leas has placeholders only. In a native-only client this is a stored row that can never dial. In the 2026-11-19 Real Test sample, WireGuard (10 links) and TUIC (8 links) were the largest live-upstream placeholders, but that is 18 of 120,405 links: the ranking applies to the non-dialable set, not to feed prevalence.
2. **No QUIC transport.** `vless-quic` rows from feeds parse (`TransportConfig::Quic`) but are refused at dial. Ferrox has a pooled QUIC transport with 0-RTT and migration.
3. **No HTTP-header TCP masquerade.** Our `type=http` maps to HTTP/2 `v2rayhttp`, not xray's `tcpSettings.header.type=http` camouflage. Ferrox implements both.
4. **No HTTP-proxy upstream.** Our HTTP module is inbound-only; an `http://user:pass@host` profile is stored but not dialable natively.
5. **No SOCKS4/4a client.** SOCKS5 is done.
6. **AnyTLS UoT** is a leas advantage, not a gap; ferrox explicitly returns `udp_lane_supported = false`.

## 4. Functional gaps on ferrox's side

Ferrox has no profile database, subscriptions, importers, TUI, per-link scheduler, failure-class persistence or purge policy. It is a core. Concretely, leas carries things ferrox does not:

- Turso-backed endpoint/profile store, subscription refresh, Telegram `t.me/s/<channel>` import, export, write-behind batching.
- Per-link real probe with confirmed-failure pairs and the stability ring; `SIGMA`/Purgatory/Active bands and purge.
- TUI, sniffer telemetry, job queue, per-country routing defaults with geo-inventory gating.
- DNSCrypt resolver pool (`leas-dns`: stamps, DoH/DoT/DoQ/DNSCrypt, latency probe). Ferrox plans DNSCrypt (row 102); its DNS app is otherwise broader (DoT/DoH/DoQ/FakeDNS/cache/rules).
- Native SIP003 plugin framing (`v2ray-plugin`, `obfs-simple`); ferrox lists it as planned.
- Trojan-Go's layered `ss;method:password` form.
- AnyTLS UoT v2.
- TLS 1.2 fallback for legacy servers; ferrox's stock lane has no TLS 1.2.

## 5. Memory efficiency

The two designs optimise different budgets. Ferrox optimises **per-operation** cost and gates it with a counting allocator; leas optimises **per-tunnel resident cost** and app churn, and gates a small number of hot paths.

These are not head-to-head results. Ferrox's matrix has no leas arm; its numbers are project claims checked by its own named checkers, and many method-page operation rows are still `UNBLESSED`. The leas figures come from its own hotpath gate and allocation profiler. Only the code-true buffer and stride values are directly comparable.

### 5.1 Design comparison

| Dimension | leas | ferrox |
|---|---|---|
| Allocator | mimalloc 3.6.1 (`mimalloc-safe`), tuned: THP off, full-retain off, reclaim 0, `generic_collect=512`; purge at job boundaries; `std-alloc`/`mem-trace` build switches | Process default allocator. `ferrox-core::alloc_count::Counting` is installed only in test/bench binaries |
| Allocation gates | 5 exact rows: VLESS header 1 alloc/50 B, Vision header 1, VLESS peel 0, TLS 1.3 seal 16 KiB 0, open 0 (`crates/leas-hotpath/src/main.rs`) | 1,228 count rows across 57 method pages, 1,087 carrying a numeric value (141 `UNBLESSED`); 169 rows keyed on allocation, 146 of them exactly zero; 416 exact-zero claims overall; 20 exact instruction rows (`scripts/method-counts.txt`, `scripts/expected-ops.txt`) |
| Copy discipline | TLS records sealed/opened in place; Vision peel zero-copy; request header withheld and coalesced with the first payload (`first_flight.rs`); relay copies buffer → tunnel | Zero user-space copies claimed and gated for SS (`open_in_place`), SS2022 (0 read, 1 written), VMess frames (caller's buffer). Vision: 2 framed, 0 after switch |
| Syscall discipline | Not counted or gated. TLS `poll_write` seals **one 16 KiB record per call** (`record/stream.rs:962`), so a 64 KiB relay write is 4 socket writes; relay reads/writes one buffer per round | Counted per method and batched: SS `readv`/`writev` of 4×16 KiB (`CHUNKS_PER_BATCH=4`), SS2022 8 chunks, VMess 16 frames per write, gRPC coalesces 256 KiB |
| Per-flow buffers | 2×16 KiB idle, promoted to 64 KiB on a full read; TLS record windows ≈16 KiB read + ≈16 KiB write reserved once; pool is `POOL_CAP=64` per class | VMess flow: `WIRE_LEN` 273,537 B + `READ_PLAIN` 131,072 B zeroed once ≈ 395 KiB; SS: one 16 KiB chunk buffer + relay; splice pipes 8 KiB–1 MiB, dynamically scaled to 44 MiB at 64 flows |
| Concurrency | tokio tasks; idle tunnel = parked task | Raw TCP: fixed poll/splice worker pool, peak 10 threads (Linux) at 8 flows; carried legs: **one parked thread per idle leg** (`docs/concurrency.md`) |
| App-level attribution | `leas-memtrace` per-module allocation tracer over the real app and workloads; boot with a real 3 000-endpoint DB: peak 10.85 MB, 2.78 M allocations, profile load 210 k of it; idle ≈100 allocs/s | Per-method pages; matrix reports peak RSS/CPU/threads per cell, but results live in CI artifacts, not in the tree |
| Crypto implementation | ring + RustCrypto, `#![forbid(unsafe_code)]`; one allocation per Vision connect | Hand-written ChaCha20/Poly1305/AES-GCM with portable + SSE2/NEON/AVX2/AVX512 backends; unsafe SIMD, differential-tested |

### 5.2 Measured or code-true numbers

- **VLESS request header**: ferrox 0 allocations, 296-byte stack buffer, exact length reserved per address family (`docs/function/vless.md`). leas 1 allocation / 50 B, gated. Both keep the header off a second write.
- **Relay buffer pool**: leas reuses 16/64 KiB windows so steady state stops calling the allocator; cold windows still zero-fill. Ferrox's `RelayBuf` pool makes the same trade and gates the reuse (`a_reused_relay_window_is_not_zeroed`).
- **Shadowsocks**: ferrox gates 0 allocations and 0 copies on the steady chunk path; leas asserts "steady-state chunk path allocates nothing" in a comment but has no counting-allocator gate, because a unit test cannot install a global allocator.
- **TLS record layer**: both seal/open in place with zero allocation. leas writes one record per `AsyncWrite::poll_write`. Ferrox's VLESS encryption record layer batches up to eight 8 KiB records into one `write_all`; its stock rustls lane is not measured here.
- **Per-flow resident cost**: on an idle TLS tunnel leas is roughly 64 KiB (relay 32 KiB + record windows ≈32 KiB) before protocol state; a ferrox VMess flow reserves ≈395 KiB of windows. Ferrox's throughput batching is paid for in resident memory; leas's 16→64 KiB promotion is the cheaper default for a desktop client with hundreds of mostly-idle profiles.
- **Concurrency**: leas parks a tokio task per leg; ferrox parks a kernel thread per carrier leg, which is the larger per-idle-flow cost. Its raw path avoids that with the fixed worker pool.
- **Pool bound discrepancy**: `AGENTS.md` states the relay pool is "64 per size class = 2 MiB". `inbound/outbound.rs` actually caps each class at 64, i.e. 1 MiB of small buffers + up to 4 MiB of large buffers = 5 MiB worst case. Not a defect, but the documented bound is wrong.

### 5.3 What ferrox proves that leas does not

- Per-method zero-copy and zero-allocation claims are gated with a counting allocator in the binary under test; leas gates 5 rows and otherwise relies on per-module memtrace attribution.
- Syscall count is a first-class number for every method; leas has none.
- Byte-identical differential tests make a rewrite of a cipher or framing safe; leas buys the same assurance from audited crates instead (a defensible trade given `forbid(unsafe_code)`).
- Peak RSS, CPU per GiB and thread count are compared against xray-core/sing-box/zeronet per cell. leas has allocation totals and boot CPU, but no per-protocol cross-engine memory table.

## 6. TLS and security posture

- leas is engine-only: one `ClientHelloSpec` roster (71 profiles), REALITY with Spider-X, ECH, TLS 1.2 fallback, `WebPkiVerifier` with SPKI pin, ring-only crypto, `zeroize` contracts. No kTLS, no session resumption, no BoringSSL lane.
- ferrox has two TLS lanes (stock/shaped rustls and BoringSSL for TLS 1.2-only suites), 50 uTLS names, ECH, REALITY server, OCSP stapling server-side, kTLS, and its own record layer with SIMD. It writes its own AEAD primitives; leas does not.
- For a client whose threat model is fingerprinting, leas's roster (69 generated JA4-faithful entries) is deeper than ferrox's 31 presets, and its REALITY client plus Spider-X is a complete path. ferrox's REALITY client claim is inconsistent across its docs: README row 39 says the client dials raw and every carrier, while `docs/method-superset.md` says "client unwired". Treat that row as unverified until checked against code.

## 7. Actions worth taking

Ranked by client impact per unit of work:

1. **Add per-method syscall and allocation gates** to `leas-hotpath` for VLESS, Trojan, VMess, SS and AnyTLS relay paths: count `poll_write`/`write` calls and allocations around one full relay round. This is the single largest evidence gap versus ferrox; it needs a counting stream, not a global allocator.
2. **Batch TLS records on write** (seal up to N records into one `write_all`, as ferrox does) and measure it. Today a 64 KiB bulk write costs 4 socket writes. Only do this with a gate; an unbounded batch grows latency.
3. **Fix the stale capability documents**: `capability.rs` still says the proxy UDP leg is missing, while `inbound/mod.rs::run_proxy_leg` implements it; its `NATIVE_KINDS` comment claims the list must be exactly the seven Auto-resolve kinds, yet `kind_supported` also admits SOCKS5 and `NATIVE_KINDS` has no production reader; `protocols.md` still presents subprocess build columns as available although production is native-only. All three mislead a reader about what the client can dial.
4. **Decide the native roster**: TUIC v5 and WireGuard are the largest missing client-protocol placeholders in the 2026-11-19 sample (10 and 8 links of 120,405), not proven common across feeds. Hysteria v1, HTTP-proxy upstream and the QUIC transport each had 1 link. Hysteria v1 and ShadowTLS are lower value. QUIC transport and HTTP-header masquerade are transport-level rows to consider before adding more protocols.
5. **Correct the relay-pool bound** in `AGENTS.md` to the code-true 5 MiB, or lower `POOL_CAP` for the large class if 5 MiB is not intended.

Do not adopt ferrox's hand-written cipher stack. Its copy/syscall wins come with unsafe SIMD and a crypto maintenance surface that leas deliberately avoids; ring/RustCrypto already delivers in-place AEAD with zero per-record allocation.

## 8. Evidence index and limits

Read:

- `thirdparty/ferrox`: `README.md` (protocol matrix, rows 1–144), `docs/method-superset.md`, `docs/concurrency.md`, `docs/benchmarks/matrix.md`, `docs/function/{vless,vmess,shadowsocks,shadowsocks-2022,anytls,record-layer}.md`, `crates/ferrox-core/src/{tuic,vless}.rs`, `crates/ferrox-app/src/*` module list.
- leas: `docs/reference/native-core.md`, `docs/reference/protocols.md`, `crates/leas-native/src/{capability.rs,protocol/mod.rs,transport/mod.rs,inbound/outbound.rs,inbound/mod.rs}`, `crates/leas-hotpath/src/main.rs`, `crates/leas-tls/src/record/{mod.rs,stream.rs}`, `crates/leas-proto/src/proto_spec/ss_method_support.rs`, `docs/research/2026-11-13-allocation-profile.md`, `AGENTS.md`.

Limits:

- No ferrox or leas benchmark was run here. Throughput/RSS comparisons in ferrox's matrix are not in the tree (`matrix-results.json` is a CI artifact).
- Ferrox's state statements are internally inconsistent: TUIC/AnyTLS are "planned" in README row 23 but implemented in `docs/method-superset.md` and dispatched by `ferrox-app/src/proxy.rs`; Commander is implemented in README row 128, planned in the ledger, and has an `engine-api` page whose counts are all `UNBLESSED`. Dispatch arms plus method pages were treated as authoritative, not the plan tables.
- leas's native transport/protocol matrix was read from code and docs, not exercised end to end on this machine; the real-core e2e rows in `leas-oracles` were not run.
