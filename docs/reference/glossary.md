# Glossary

Terms as this project uses them. Each entry is one line; the owning document is linked where the detail lives.

| Term | Meaning |
|---|---|
| **capability::supported / NATIVE_KINDS** | The connect-time native gate in `crates/leas-native/src/capability.rs`: `NATIVE_KINDS` is the six kinds Auto may resolve onto native, `support_reason` the config-aware verdict whose text doubles as the `[real]` marker. Unknown values fail closed |
| **Config type** | The proxy protocol of a profile: `ProtocolKind`, string form `vmess`, `ss`, `ss-2022`, `any-tls` and so on (`crates/leas-proto/src/proto_spec/kinds.rs`) |
| **Counted\<S\>** | Byte-counting `AsyncRead`/`AsyncWrite` wrapper in `crates/leas-native/src/telemetry.rs` that feeds shared atomics as bytes move |
| **DnsResolver** | Per-instance resolver in `leas-dns`: DNSCrypt public resolver list (DoH, DoT, DoQ), on-disk cache; IP literals short-circuit |
| **EndpointInfo** | In-memory enrichment cache (`AppState.endpoint_info`): resolved IPs, inbound and outbound country, whitelist flags, exit IP |
| **Fast Ping** | Transport-level latency test (TCP handshake, UDP datagram, QUIC handshake) dispatched by `FastPingManager` in `crates/leas-core/src/ping/adapters`; unsupported protocols fall through to the real probe |
| **HostFeatures** | Whitelist membership from `leas-host-features`: `sni_whitelisted`, `ip_whitelisted`, `cidr_whitelisted`. IPv4-only whitelists, zero false positives |
| **Inbound / Outbound** | Local listening side that accepts traffic, or the remote proxy connection that carries it |
| **Latency** | The typed per-link measurement on `profile_stats`: `real_delay` (full probe span), `fast_delay` (transport span), `ip` (exit IP), `auth` (auth flag). Schema 19 made it a struct, so one row can hold a real and a fast delay at once; the real delay wins |
| **LinkContext** | Per-link policy surface in the native core (`crates/leas-native/src/context.rs`): `is_tls()`, `server_name()`, `alpn_tokens()`, `curve_ids()`. Every phase reads its policy here |
| **Location** | GeoIP lookup result from `leas-geoip`: country ISO code plus optional city, from a GeoLite2-City mmdb |
| **NativeActivityLog** | Session-only ring of native connection traces (2000 rows) backing the Native Activity tab; never persisted |
| **NativeCoreServer** | The in-process core in server mode (`crates/leas-native/src/server/mod.rs`): local SOCKS5 and optional HTTP CONNECT listener, proxy-all engine. `shutdown()` is the only teardown that guarantees the ports are free on return |
| **Plugin mux** | v1.mux.cool framing carried by a SIP003 plugin row; the codec lives once in `crates/leas-native/src/transport/mux.rs`, the Shadowsocks side takes a per-session codec |
| **profile_stats** | One row per `(protocol_id, endpoint_id)` pair and the only per-profile persistent state: latency, auth flag, failure marker, speed, traffic counters, purge reason. Written write-behind through `LinkWriter` (`crates/leas-db/src/write_behind.rs`) in column groups; no per-attempt history table |
| **ProtocolId / uid** | Content hash identifying a protocol config: `uid = sig ^ cred_hash`, computed by the per-kind identity writer over non-default fields only, endpoint host and port excluded, so one config on many servers dedups to one `Protocol` row. 64-bit, never zero |
| **PurgeReason** | Why a link left the Active view permanently: `RealityFallback`, `CertificateMismatch`, `CertificateExpired`, `NotTls`, `ConfigInvalid`, `TransportRejected`, `OriginUnreachable`. Written by the real probe's tagged evidence through `ops::purge::reason_for`, cleared only by a data-carrying success. The `error_ttl_hours` sweep never touches it (ADR 0006) |
| **Purgatory** | The view of profiles not confirmed live and recent: links whose newest live link aged past the TTL (default 7 days), plus every link carrying a `PurgeReason`. Retention (default 30 days) is when the sweep deletes them |
| **PurgatoryView** | The list filters `Active`, `Purgatory`, `All`, computed in SQL from the live-only `rank_newest_seen` against the configured TTL. `Active` is `>= now - ttl` and loads no purged link; `Purgatory` is below it. There is no system-group row and no `ALL_GROUP_ID`; the filters are predicates over the `endpoint_groups` link (ADR 0006) |
| **REALITY** | XTLS's TLS-resemblance mechanism: the server relays to a real site, and the client proves its key. VLESS and Trojan only. Engine: `crates/leas-tls` |
| **SIP003 / PluginSpec** | The Shadowsocks plugin extension, stored as one typed lossless `PluginSpec` (`SsConfig.plugin`). Every wire key lands in a typed field or `extra`, and an unsupported spelling is preserved (`*::Invalid`) rather than rewritten. Served natively: simple-obfs `obfs=http`/`obfs=tls` and v2ray-plugin `mode=websocket`. There is no `obfs=plain` (that is ShadowsocksR vocabulary) |
| **Stream settings** | The per-outbound xray block carrying transport and TLS (`streamSettings` in the generated JSON); produced by the protocol config's inject arm, not maintained by hand |
| **Subscription group** | A named group of endpoints fetched from a subscription URL; membership is the `endpoint_groups` link |
| **Test-cell link** | The endpoint's representative link, `EndpointRow::representative_link_index`, the minimum of the ordering key. The Test column's content is the row's tier band: 0/1 delay, 2 blank, 3/4 `[real]`/`[fast]`, 5 `[name]`, 6 the purge label |
| **Transport** | The network layer under a proxy protocol: TCP, WebSocket, gRPC, HTTP/2, QUIC, mKCP, HTTPUpgrade, XHTTP. Only VLESS, VMess and Trojan carry one |
| **uTLS fingerprint** | Browser TLS Client Hello emulation (Chrome, Firefox, Safari and the roster in `leas-tls`); the id is stored as text on the config |
