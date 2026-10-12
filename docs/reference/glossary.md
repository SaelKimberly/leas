# Glossary

Domain terms as this project uses them. (Folded from the retired the retired context page.)

| Term | Meaning |
|---|---|
| **Inbound / Outbound** | Local listening side that accepts traffic (SOCKS, HTTP) / remote proxy server connection that carries it |
| **Subscription group** | A named group of endpoints fetched from a subscription URL; membership is the `endpoint_groups` link |
| **ProtocolId / uid** | Content hash identifying a protocol config: `uid = sig ^ cred_hash`, computed by the per-kind binary identity writer over non-default fields only, endpoints (host/port) excluded — one config on many servers dedups to one `Protocol` row. 64-bit, never zero |
| **PurgatoryView** | The list filters — `Active` / `Purgatory` / `All` — computed in SQL from the live-only `rank_newest_seen` against the configured TTL. `Active` is `>= now − ttl` (loads no purged link); `Purgatory` is below it, covering both the aged band and endpoints with no live link. There is no system-group row and no `ALL_GROUP_ID`; the filters are predicates over the `endpoint_groups` link (ADR 0006) |
| **Purgatory** | The view of profiles not confirmed live and recent: links whose newest live link aged past the TTL (default 7 days), plus every link carrying a `PurgeReason`. Retention (default 30 days) is when the sweep deletes them |
| **PurgeReason** | Why a link left the Active view permanently — `RealityFallback`, `CertificateMismatch`, `CertificateExpired`, `NotTls`, `ConfigInvalid`, `TransportRejected`, `OriginUnreachable`. Written by the real probe's tagged evidence via `ops::purge::reason_for`; cleared only by a data-carrying success. The `error_ttl_hours` sweep does not touch it (ADR 0006) |
| **SIP003 / PluginSpec** | The Shadowsocks plugin extension, stored as one typed, lossless `PluginSpec` (`SsConfig.plugin`). Total by construction: every wire key lands in a typed field or `extra`, and an unsupported spelling is preserved (`*::Invalid`) rather than rewritten. Served natively: simple-obfs `obfs=http`/`obfs=tls` and v2ray-plugin `mode=websocket`. There is **no `obfs=plain`** (that is ShadowsocksR's vocabulary) |
| **Plugin mux** | v1.mux.cool framing carried by a SIP003 plugin row; the codec lives once in `transport/mux.rs`, the SS side takes a per-session codec |
| **Test-cell link** | The endpoint's representative link — `EndpointRow::representative_link_index`, the argmin of the ordering key. The Test column's content IS the row's tier band: 0/1 → delay, 2 → blank, 3/4 → `[real]`/`[fast]`, 5 → `[name]`, 6 → the purge label |
| **Latency** | The typed per-link measurement on `profile_stats`: `Latency::Real { delay, ip }` or `Latency::Fast { delay }` — the variant IS the provenance (tier 0 vs 1) |
| **Fast Ping** | Transport-level latency test (TCP handshake / UDP datagram / QUIC handshake) dispatched by `FastPingManager`; unsupported protocols fall through to the real probe |
| **DnsResolver** | Per-instance resolver (`leas-dns`): DNSCrypt public resolver list (DOH/DOT/DOQ), on-disk cache; IP literals short-circuit |
| **Location** | GeoIP lookup result (`leas-geoip`): country ISO code + optional city, from a GeoLite2-City mmdb |
| **HostFeatures** | Whitelist-membership result (`leas-host-features`): `sni_whitelisted` / `ip_whitelisted` / `cidr_whitelisted` (IPv4-only whitelists) |
| **profile_stats** | One row per `(protocol_id, endpoint_id)` pair — the only per-profile persistent state: latency, failure marker, speed, traffic counters. Written write-behind through `LinkWriter` in column groups. No per-attempt history table |
| **EndpointInfo** | In-memory enrichment cache (`AppState.endpoint_info`): resolved IPs, inbound/outbound country, whitelist flags, `resolved_at_secs` |
| **LinkContext** | Per-link policy decision surface in the native core (`leas-native/src/context.rs`): `is_tls()`, `server_name()`, `alpn_tokens()`, `curve_ids()` — every phase reads its policy here, never re-derives it |
| **NativeCoreServer** | The in-process core in server mode: local SOCKS5 (+ optional HTTP CONNECT) listener, proxy-all engine; `shutdown()` is the only teardown that guarantees the ports are free on return |
| **capability::supported / NATIVE_KINDS** | The connect-time native gate (`leas-native/src/capability.rs`). Unknown or native-worse values fail closed |
| **NativeActivityLog** | Session-only ring of native connection traces (2000 rows) backing the Native Activity tab; never persisted |
| **Counted\<S\>** | Byte-counting `AsyncRead`/`AsyncWrite` wrapper feeding shared atomics as bytes move |
| **Transport / Stream Security / Config Type** | Network layer (TCP, WS, gRPC, QUIC…) / TLS-REALITY-None wrapper / the proxy protocol |
| **REALITY** | XTLS's TLS-resemblance mechanism |
| **uTLS fingerprint** | Browser TLS fingerprint emulation (Chrome, Firefox, Safari…) |
