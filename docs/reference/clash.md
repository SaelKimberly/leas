# Clash (mihomo) YAML mapping

This page answers two questions: for a Clash/mihomo YAML key, which field of our protocol model does it reach and in which direction; and for a field of our model, which Clash key carries it. It covers the per-entry conversion (`proxies:` array elements) and the `clash_mixin` overlay the app merges into the config it hands to a core. It does not document share-URL syntax, which [`protocols.md`](protocols.md) owns, and it does not restate mihomo's own manpage: only the keys that touch our code, plus the keys mihomo accepts and we drop.

Reference behaviour comes from the mihomo v1.18 sources vendored at `thirdparty/mihomo/`, with `thirdparty/quirktiva/` as the second implementation that accepts the same YAML.

## 1. Where Clash YAML meets the code

| Surface | Code | Direction |
|---|---|---|
| `ClashProxy`, one `proxies:` array element | `crates/leas-proto/src/clash/mod.rs` | read and write (serde `Serialize`/`Deserialize`) |
| `XxxConfig::try_from_clash_proto(&ClashProxy)` | `crates/leas-proto/src/proto_spec/<proto>.rs` | read: Clash entry to `ParsedProto` |
| `XxxConfig::to_clash_proto(&EndpointEssentials)` | same files | write: config plus endpoint to a Clash entry |
| `ProtocolConfig::try_from_clash` | `crates/leas-proto/src/proto_spec/mod.rs` | read: dispatches over all 21 variants |
| `ProtocolConfig::to_clash` | same file | always an error: host and port live in `EndpointEssentials`, so use `to_clash_proto` |
| `parse_clash_mixin` | `crates/leas-core/src/config_builder/clash_mixin.rs` | read: free-form JSON/YAML to `serde_json::Value` |
| mixin merge | `ProcessManager::start`, `ProcessManager::rewrite_config` in `crates/leas-core/src/process.rs` | write: top-level key replacement into the generated core config |

Two facts follow from that table and shape everything below.

First, `ClashProxy` is a Rust type, not a YAML binding: no crate in this workspace depends on a YAML deserializer for it. Field keys are therefore the Rust field names verbatim (`skip_cert_verify`, `ws_opts`, `alter_id`), because the payload structs carry no `rename_all`; only the `type:` tag values are kebab-cased, by `#[serde(tag = "type", rename_all = "kebab-case")]`. A reader that does bind YAML must spell the keys the way mihomo spells them, which is the "mihomo key" column in the tables below.

Second, nothing in the workspace parses a whole Clash profile. `proxy-groups`, `proxy-providers`, `rules`, `rule-providers`, `dns`, `tun`, `sniffer`, `profile` and the other top-level groups have no struct and no reader; they reach a core only as mixin keys (section 7).

## 2. Proxy entry envelope

Every variant starts with the same three keys plus the tag.

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `name` | `name: String` | `remarks: Option<TinyText>` | both; empty `name` reads as `remarks: None` |
| `type` | enum tag | `ProtocolKind` (chosen by the variant) | both |
| `server` | `server: String` | `EndpointEssentials.host` | both, stored verbatim |
| `port` | `port: u16` | `EndpointEssentials.port`, and `ports = [port]` | both |

`EndpointEssentials.host_type` is derived on read by `clash_to_endpoint`: the `server` string that parses as `IpAddr::V4` becomes `HostKind::Ipv4`, `V6` becomes `Ipv6`, anything else `Dns`. A host written as `[2001:db8::1]` is not stripped of its brackets, so it stays a `Dns` host.

The `type` values the enum accepts, and what each one becomes:

| YAML `type` | Variant | Our protocol |
|---|---|---|
| `vmess` | `ClashProxy::Vmess` | `ProtocolKind::Vmess` |
| `vless` | `ClashProxy::Vless` | `ProtocolKind::Vless` |
| `trojan` | `ClashProxy::Trojan` | `ProtocolKind::Trojan` |
| `ss` | `ClashProxy::Shadowsocks` | `ProtocolKind::Shadowsocks`, or `Shadowsocks2022` for a `2022-blake3-*` cipher |
| `ssr` | `ClashProxy::ShadowsocksR` | `ProtocolKind::ShadowsocksR` |
| `socks5` | `ClashProxy::Socks5` | `ProtocolKind::Socks` |
| `http` | `ClashProxy::Http` | `ProtocolKind::Http` |
| `tuic` | `ClashProxy::Tuic` | `ProtocolKind::Tuic` |
| `hysteria2` | `ClashProxy::Hysteria2` | `ProtocolKind::Hysteria2` |
| `hysteria` | `ClashProxy::Hysteria` | `ProtocolKind::Hysteria` |
| `wireguard` | `ClashProxy::Wireguard` | `ProtocolKind::WireGuard` |
| `naive` | `ClashProxy::Naive` | `ProtocolKind::Naive` |
| `anytls` | `ClashProxy::Anytls` | `ProtocolKind::AnyTls` |
| `shadowtls` | `ClashProxy::Shadowtls` | `ProtocolKind::ShadowTls` |
| `tor` | `ClashProxy::Tor` | `ProtocolKind::Tor` |
| `ssh` | `ClashProxy::Ssh` | `ProtocolKind::Ssh` |
| `tailscale` | `ClashProxy::Tailscale` | `ProtocolKind::Tailscale` |
| `snell` | `ClashProxy::Snell` | none, conversion fails |
| `direct` | `ClashProxy::Direct` | none, conversion fails |
| `dns` | `ClashProxy::Dns` | none, conversion fails |
| `reject` | `ClashProxy::Reject` | none, conversion fails |

A `type` outside this list (`gost-relay`, `mieru`, `sudoku`, `masque`, `trusttunnel`, `openvpn`, `rematch`) has no variant, so deserializing the entry fails instead of producing an empty config. `snell`, `direct`, `dns` and `reject` do deserialize, and `ProtocolConfig::try_from_clash` rejects them with `ParseError::Unknown("cannot convert clash proxy type to outbound protocol")`.

## 3. Keys no converter touches

These keys are common to mihomo proxies and appear in many feeds. No conversion reads or writes them. Where a struct field exists, `to_clash_proto` leaves it absent and a deserialized row keeps the value in the struct, where nothing consumes it. Where no field exists, serde ignores the key (no `deny_unknown_fields`) and serialization cannot emit it.

| mihomo key | Status |
|---|---|
| `udp` | field exists on the vmess, vless, trojan, socks5 and direct structs; never set by a converter, never read by one |
| `tfo` | field exists on the vmess, vless and trojan structs; never set by a converter, never read by one |
| `mptcp`, `interface-name`, `routing-mark`, `ip-version`, `dialer-proxy`, `prefer`, `client-fingerprint` | no struct field; ignored on read, never written |
| `smux` (the whole multiplex block, including `brutal`) | no struct field; mux is carried only by the `vless` `mux` bool (section 6.2) |
| `ech-opts` | no struct field |

Two consequences worth knowing when reading a feed. `client-fingerprint` has no home: our uTLS choice (`TlsOpts.fp`) travels in `fingerprint` instead, and only for vmess and trojan (sections 6.1 and 6.3). `smux` has no home either, so a feed that requests multiplexing through `smux` loses it.

## 4. Security and TLS keys

`SecurityConfig` has two shapes: `TlsConfig::Tls(TlsOpts)` for a plain TLS layer and `TlsConfig::Reality(RealityOpts)`. The conversion is `security_to_clash_tls` and `clash_tls_to_security` in `crates/leas-proto/src/proto_spec/common.rs`.

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `tls` | `tls: Option<bool>` (vmess, vless, socks5, http, naive, shadowtls, anytls), `tls: bool` on trojan | `SecurityConfig.tls` | both; written `true` for a plain TLS layer, absent for REALITY, and `true` on trojan even when the layer is empty |
| `servername` | `servername` | `TlsOpts.sni`, `RealityOpts.sni` | both |
| `skip-cert-verify` | `skip_cert_verify` | `TlsOpts.insecure` | both |
| `alpn` | `alpn: Option<Vec<String>>` | `TlsOpts.alpn` (single string) | both, but lossy: read keeps only the first element, write emits a one-element array |
| `fingerprint` | `fingerprint` | `TlsOpts.fp` | both, vmess and trojan only |
| `reality-opts.public-key` | `reality_opts.public_key` | `RealityOpts.pbk` | both, vless only |
| `reality-opts.short-id` | `reality_opts.short_id` | `RealityOpts.sid` | both, vless only |
| `reality-opts.support-x25519mlkem768` | `support_x25519mlkem768` | none | parsed, ignored on read, never written |

`sni` is not a field in any Clash struct; only `servername` is. mihomo spellings that write SNI as `sni` (trojan, tuic, hysteria in some feeds) therefore lose the name on read. `mldsa65-verify` (`RealityOpts.mldsa65_verify`, share-link key `pqv`) has no Clash key in either direction.

TLS on read depends on the protocol, not on the YAML alone:

| Protocol | Read | Write |
|---|---|---|
| vmess, vless, socks5, http, naive, anytls, shadowtls | from the `tls` key; `tls: false` or absent means `security.tls = None` | plain TLS writes `tls: true`; REALITY writes no `tls` key |
| trojan | `Some(c.tls)`, and the struct defaults `tls` to `true` when absent | `tls` defaults to `true` |
| tuic, hysteria2, hysteria | `Some(true)` regardless of the YAML, because TLS is part of the protocol | no `tls` key exists in those three structs |
| anytls | additionally collapses an all-empty `Tls` block back to no security, so `tls: true` with no parameters round-trips to the same identity | always `tls: true` |

## 5. Transport keys

`transport_to_clash` and `clash_transport_to_transport` own this mapping. The `network` value is what selects a transport.

| `network` value | Read result | Written from | Written as |
|---|---|---|---|
| `ws`, `websocket` | `TransportConfig::Ws` | `TransportConfig::Ws` | `ws` |
| `grpc` | `TransportConfig::Grpc` | `TransportConfig::Grpc` | `grpc` |
| `h2`, `http` | `TransportConfig::Http`, using `h2-opts` | `TransportConfig::Http` | `http` with `h2-opts` |
| `kcp`, `mkcp` | `TransportConfig::Kcp`, using `mkcp-opts` | `TransportConfig::Kcp` | `kcp` |
| `tcp` or absent | `TransportConfig::Tcp` | `TransportConfig::Tcp` | key omitted |
| anything else (`xhttp`, `quic`, `mekya`) | `TransportConfig::Tcp`, silently | `TransportConfig::Quic`, `HttpUpgrade`, `XHttp` | key omitted |

The last row is the largest fidelity gap in this direction: an XHTTP, QUIC or HTTPUpgrade config exports as a plain TCP entry, because no Clash key encodes those transports in our structs.

Sub-option mapping:

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `ws-opts.path` | `ws_opts.path` | `WebSocketConfig.path` | both |
| `ws-opts.headers` | `ws_opts.headers` | `WebSocketConfig.headers` | both; the `Host` entry moves to `WebSocketConfig.host` on read and back into `headers.Host` on write, matched case-insensitively |
| `ws-opts.max-early-data` | `max_early_data` | `WebSocketConfig.max_early_data` | both |
| `ws-opts.early-data-header-name` | `early_data_header_name` | `WebSocketConfig.early_data_header_name` | both |
| `ws-opts.v2ray-http-upgrade` | `v2ray_http_upgrade` | `WebSocketConfig.v2ray_http_upgrade` | both |
| `ws-opts.v2ray-http-upgrade-fast-open` | `v2ray_http_upgrade_fast_open` | `WebSocketConfig.v2ray_http_upgrade_fast_open` | both |
| `grpc-opts.grpc-service-name` | `grpc_service_name` | `GrpcConfig.service_name` (and `.path`) | both; write falls back to `path` |
| `grpc-opts.grpc-user-agent` | `grpc_user_agent` | `GrpcConfig.user_agent` | both |
| `grpc-opts.ping-interval` | `ping_interval` | `GrpcConfig.ping_interval` | both |
| `grpc-opts.max-concurrent-streams` | `max_concurrent_streams` | none | parsed, never written, ignored on read |
| `h2-opts.path` | `h2_opts.path` | `HttpConfig.path` | both |
| `h2-opts.host` | `h2_opts.host: Option<Vec<String>>` | `HttpConfig.host` (single string) | both, lossy: read takes the first element only, write emits a one-element list |
| `http-opts.method`, `http-opts.path`, `http-opts.headers` | `http_opts` | none | parsed into the struct and dropped in both directions; `HttpConfig.method` and `.headers` have no Clash key |
| `mkcp-opts.mtu`, `tti`, `uplink-capacity`, `downlink-capacity`, `congestion`, `write-buffer`, `read-buffer`, `seed`, `header` | `mkcp_opts` | the matching `KcpConfig` field (`header` is `header_type`) | both |
| `xhttp-opts.path`, `max-download-size`, `early-data-header`, `reuse.enabled`, `reuse.extra-path` | `xhttp_opts` | none | parsed into the struct, never read into a transport, never written |

`HttpConfig.host` is host-free on export: `to_clash_proto` passes `server = None` into `transport_to_clash`, so an unset host stays unset and the endpoint host never leaks into `h2-opts.host`, which would re-import into the identity-hashed config. Only the legacy in-config path can fall back to the endpoint host.

`GrpcConfig.authority` and `GrpcConfig.mode` have no Clash key. `HttpUpgradeConfig` and `XHttpConfig` are reachable from share URLs and JSON, not from Clash.

## 6. Per-type mapping

Tables are keyed by the Clash key; the "Our field" column gives the reverse direction. A row marked "ignored" means the key deserializes into a struct field that no conversion reads.

### 6.1 `vmess`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `uuid` | `uuid` | `uuid: String` | both |
| `cipher` | `cipher` | `security.enc` | both; write falls back to `auto` when `enc` is absent, read always sets `enc` from the key |
| `alterId` | `alter_id` | `alter_id: Option<TinyText>` | both; decimal string in our model, `u32` here, so a non-numeric `alter_id` is written as absent |
| `network` | `network` | `transport` | both, section 5 |
| `tls`, `servername`, `skip-cert-verify`, `alpn`, `fingerprint` | see section 4 | `security` | both |
| `ws-opts`, `grpc-opts`, `h2-opts`, `http-opts`, `mkcp-opts` | see section 5 | `transport` | both, except `http-opts` |
| `udp`, `tfo` | `udp`, `tfo` | none | ignored, section 3 |

Clash carries multiplexing for any proxy through the `smux` block, which has no field here. Our model has a typed mux request only for vless (`VlessMux`), so a vmess row's `smux` is lost and its `mux` bool has no field either.

### 6.2 `vless`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `uuid` | `uuid` | `uuid: String` | both |
| `flow` | `flow` | `flow: Option<TinyText>` | both |
| `encryption` | `encryption` | `encryption: Option<TinyText>` | both |
| `mux` | `mux: Option<bool>` | `mux: Option<VlessMux>` | both, lossy: write is `VlessMux::is_active()`; read maps `true` to `Limited(8)` and `false` to `Limited(0)`, so a cap and `Unlimited` both return as the default cap |
| `network` | `network` | `transport` | both, section 5; `xhttp` reads as TCP |
| `tls`, `servername`, `skip-cert-verify`, `alpn` | see section 4 | `security` | both |
| `reality-opts.public-key`, `reality-opts.short-id` | see section 4 | `RealityOpts.pbk`, `.sid` | both |
| `ws-opts`, `grpc-opts` | see section 5 | `transport` | both |
| `xhttp-opts` | `xhttp_opts` | none | parsed, dropped both ways |
| `fingerprint` | no field on `ClashVless` | `TlsOpts.fp`, `RealityOpts.fp` | write drops it, read cannot see it |
| `udp`, `tfo` | `udp`, `tfo` | none | ignored, section 3 |

`VlessConfig.splice` and `uuid_origin` are model-only: no Clash key carries them.

### 6.3 `trojan`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `password` | `password` | `password: String` | both |
| `tls` | `tls: bool` (defaults true) | `security.tls` | both, section 4 |
| `servername`, `skip-cert-verify`, `alpn`, `fingerprint` | see section 4 | `security` | both |
| `ws-opts`, `grpc-opts` | see section 5 | `transport` | both; the struct has no `network` key, so read infers `ws` or `grpc` from which opts block is present, and write never sets `network` |
| `flow`, `flow-show` | `flow`, `flow_show` | none | parsed, never written, ignored on read; our trojan config has no flow field |
| `udp`, `tfo` | `udp`, `tfo` | none | ignored, section 3 |
| `ss-opts` (Trojan-Go Shadowsocks overlay), `ech-opts` | no field | none | the overlay is not modelled; serde ignores the key |

### 6.4 `ss`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `cipher` | `cipher` | `method: TinyText` | both; also selects `ProtocolKind::Shadowsocks2022` when the method starts with `2022-blake3-`, case-insensitively |
| `password` | `password` | `password: String` | both |
| `plugin` | `plugin: Option<String>` | `plugin.name` | both |
| `plugin-opts` | `plugin_opts: Option<String>` | `plugin` (`PluginSpec`) | both; the string is the SIP003 dialect of `key=value` pairs joined by `;`, a bare key means `1`, and the same splitter serves share URLs |
| `udp`, `udp-over-tcp` | `udp`, `udp_over_tcp` | none | parsed, never written, ignored on read |

The plugin options are not a free-form map on our side: `PluginSpec` keeps the name, the observed family, `mode`, `host`, `port`, `path`, `tls`, `mux` and a sorted `extra` map, and re-renders them with the family's own key spelling. A Clash row carrying only `plugin-opts` (no `plugin`) still builds a plugin spec with an empty name rather than dropping the options. See [`protocols.md`](protocols.md) for the share-URL spelling of the same dialect.

### 6.5 `ssr`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `cipher` | `cipher` | `method: TinyText` | both |
| `password` | `password` | `password: String` | both |
| `protocol` | `protocol` | `protocol: TinyText` | both; read also mirrors it into `params["protocol"]` |
| `obfs` | `obfs` | `obfs: TinyText` | both; read also mirrors it into `params["obfs"]` |
| `protocol-param` | `protocol_param` | `params["protocol_param"]` | both |
| `obfs-param` | `obfs_param` | `params["obfs_param"]` | both |

Any other key in the `params` map is model-only and has no Clash key.

### 6.6 `socks5`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `username` | `username` | `username: Option<String>` | both |
| `password` | `password` | `password: Option<String>` | both |
| `tls`, `servername`, `skip-cert-verify` | see section 4 | `security` | both |
| `udp` | `udp` | none | ignored |

`certificate`, `private-key`, `fingerprint` (mTLS and pinning) have no field.

### 6.7 `http`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `username` | `username` | `username: Option<String>` | both |
| `password` | `password` | `password: Option<String>` | both |
| `tls`, `servername`, `skip-cert-verify` | see section 4 | `security` | both |
| `headers` | `headers: Option<HashMap<String, String>>` | none | parsed, never written, ignored on read |

### 6.8 `tuic`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `token` | `token` | `uuid` and `password` | both; write joins as `uuid:password` when the password is non-empty and as `uuid` alone otherwise; read splits on the first `:` only when the left side is non-empty, otherwise the whole token is the uuid and the password is empty |
| `udp-relay-mode` | `udp_relay_mode` | `udp_relay_mode: Option<TinyText>` | both |
| `congestion-controller` | `congestion_controller` | `congestion_control: Option<TinyText>` | both |
| `servername`, `skip-cert-verify`, `alpn` | see section 4 | `security` | both, with TLS forced on |
| `ip`, `heartbeat-interval`, `reduce-rtt`, `request-timeout` | the matching fields | none | parsed, never written, ignored on read |

The QUIC tuning keys mihomo accepts (`max-open-streams`, `cwnd`, `bbr-profile`, the four receive-window keys, `disable-mtu-discovery`, `max-datagram-frame-size`) have no field, and `sni` is not a field on `ClashTuic`, so a TUIC entry that names SNI with `sni` loses it (section 4).

### 6.9 `hysteria2`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `password` | `password` | `auth: String` | both |
| `up`, `down` | `up: Option<String>` | `up`, `down: Option<TinyText>` | read keeps the raw string (`"30 Mbps"` survives); write parses it as `u32`, so anything that is not a bare integer, and any unit suffix, is written as absent |
| `hop-interval` | `hop_interval` | `hop_interval: Option<u32>` | both |
| `obfs` | `obfs` | `obfs: Option<TinyText>` | both |
| `obfs-password` | `obfs_password` | `obfs_password: Option<TinyText>` | both |
| `servername`, `skip-cert-verify`, `alpn` | see section 4 | `security` | both, TLS forced on |
| `ports` | `ports` | none | parsed, never written, ignored on read; the endpoint carries the port list |
| `pin-sha256` | no field | `pin_sha256: Option<TinyText>` | model-only, lost in both directions |
| `obfs-min-packet-size`, `obfs-max-packet-size`, `bbr-profile`, `realm-opts`, the four receive-window keys | no field | none | not modelled |

Writing a numeric string such as `"100"` produces `up: 100`, which reads back as `"100"`: that is the only spelling that survives a round trip.

### 6.10 `hysteria` (v1)

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `auth-str` | `auth_str` | `auth: Option<String>` | both; write emits an empty string when absent |
| `protocol` | `protocol` | `protocol: Option<TinyText>` | both |
| `obfs` | `obfs` | `obfs: Option<TinyText>` | both |
| `up`, `down` | `up`, `down: Option<String>` | `up_mbps`, `down_mbps: Option<u32>` | both; write renders the integer as a string, read parses it and turns `100` into absent (the protocol default) |
| `alpn`, `servername`, `skip-cert-verify` | see section 4 | `security` | both, TLS forced on |
| `ports` | `ports` | none | parsed, never written, ignored on read |
| `auth` (the byte form), `recv-window-conn`, `recv-window`, `disable-mtu-discovery`, `fast-open` | no field | none | not modelled |

Because `100` is filtered on read, a feed that states `up: 100` explicitly and one that omits the key produce the same config.

### 6.11 `wireguard`

| mihomo key | Rust field | Our field | Direction |
|---|---|---|---|
| `private-key` | `private_key` | `private_key: String` | both |
| `public-key` | `public_key` | `public_key: String` | both |
| `pre-shared-key` | `pre_shared_key` | `preshared_key: Option<String>` | both |
| `ip` | `ip: Option<String>` | `address: TinyText` | both, not symmetric: read appends `/32` when the value has no prefix, write strips everything from the first `/` |
| `reserved` | `reserved: Option<String>` | `reserved: Option<TinyText>` | both |
| `mtu` | `mtu: Option<u32>` | `mtu: Option<TinyText>` | both; a non-numeric `mtu` is written as absent |
| `persistent-keepalive` | `persistent_keepalive` | `persistent_keepalive: Option<u32>` | both |
| `dns` | `dns: Option<Vec<String>>` | `dns: Option<Vec<String>>` | both |
| `ipv6` | `ipv6` | none | parsed, never written, ignored on read |
| `remote-dns-resolve` | no field | `remote_dns_resolve: Option<bool>` | model-only |
| `refresh-server-ip-interval`, `peers`, `amnezia-wg-option` | no field | none | not modelled |

`reserved` is a string here. A feed that writes the mihomo array form (`reserved: [209, 98, 59]`) fails to deserialize into `Option<String>`.

### 6.12 `snell`

Parsed into `ClashSnell` (`psk`, `version`, `obfs_opts`, plus the envelope) and then refused: there is no Snell config type and no `ProtocolKind` for it. `try_from_clash` returns an error naming the limitation. The same holds for an `obfs-opts` object, which the struct flattens into a single string.

### 6.13 `naive`, `anytls`, `shadowtls`

| Protocol | mihomo key | Rust field | Our field | Direction |
|---|---|---|---|---|
| `naive` | `username`, `password` | `username`, `password: String` | `username`, `password: String` | both |
| `naive` | `tls`, `servername`, `skip-cert-verify` | see section 4 | `security` | both |
| `anytls` | `password` | `password: String` | `password: Option<String>` | both |
| `anytls` | `tls`, `servername`, `skip-cert-verify` | see section 4 | `security` | both, TLS always written `true` |
| `anytls` | `idle-session-check-interval`, `idle-session-timeout`, `min-idle-session` | the matching fields | none | parsed, never written, ignored on read |
| `shadowtls` | `password` | `password: String` | `password: Option<String>` | both |
| `shadowtls` | `version` | `version: Option<u32>` | `version: Option<TinyText>` | both; a non-numeric version is written as absent |
| `shadowtls` | `tls`, `servername`, `skip-cert-verify` | see section 4 | `security` | both |

`anytls` and `shadowtls` share the plain-TLS handling of section 4; `naive` does too.

### 6.14 `tor`, `ssh`, `tailscale`

| Protocol | mihomo key | Rust field | Our field | Direction |
|---|---|---|---|---|
| `tor` | `server`, `port` | envelope only | endpoint only | both; `executable_path`, `extra_args`, `data_directory` and `torrc` have no Clash key |
| `ssh` | `user` | `user: String` | `user: Option<String>` | both; an absent model user writes as an empty string |
| `ssh` | `password`, `private-key`, `private-key-path` | `password`, `private_key`, `private_key_path` | same names | both |
| `ssh` | `host-key`, `host-key-algorithms`, `client-version` | same names | same names | both |
| `ssh` | no key | no field | `private_key_passphrase` | model-only |
| `tailscale` | `hostname` | `hostname: String` | `hostname: Option<String>` | both; empty reads as `None` |
| `tailscale` | `auth-key`, `control-url`, `state-dir`, `exit-node` | `auth_key`, `control_url`, `state_dir`, `exit_node` | `auth_key`, `control_url`, `state_directory`, `exit_node` | both |
| `tailscale` | `ephemeral`, `accept-routes` | `ephemeral: bool`, `accept_routes: bool` (both default `false`) | `Option<bool>` | both, and the read always materializes `Some(...)`, so presence is not distinguishable |
| `tailscale` | `exit-node-allow-lan-access` | same name | `Option<bool>` | both |
| `tailscale` | no key | no field | `advertise_routes` | model-only |

Neither `tor`, `ssh` nor `tailscale` has a share URL, so a Clash entry is the only text form that can produce them; `endpoint.rs` builds their identity goldens through `ProtocolConfig::try_from_clash` for exactly that reason.

## 7. The `clash_mixin` overlay

`clash_mixin` is an app setting (`AppConfig.clash_mixin: Option<String>`, edited as `Clash Mixin (JSON/YAML)` on the settings screen). `parse_clash_mixin` turns the text into a `serde_json::Value`: it tries JSON first and falls back to YAML through `yaml-rust2`. An empty or whitespace-only string yields `None`, and a YAML document whose root (or any nested value) is null, bad or an alias also yields `None`.

The merge happens when the config is written for a core: `ProcessManager::start` and `ProcessManager::rewrite_config` serialize the built config, and for every top-level key of the mixin object, replace the same-named top-level key of that config. There is no deep merge: a mixin `dns:` replaces the entire generated `dns` block. An empty mixin object changes nothing. The merge is core-agnostic, so an xray config receives the same replacement, and whether the core accepts a key is the core's decision, not a validation step here.

Because the value is a plain object merge, the keys a mixin can carry are the top-level keys of the generated config (`log`, `inbounds`, `outbounds`, `route` or `routing`, `dns`, `experimental`, ...). mihomo's own top-level groups mean nothing to leas; they are listed here only so a reader knows they have no field:

| mihomo top-level group | Keys it holds | Our field |
|---|---|---|
| general / listeners | `port`, `socks-port`, `mixed-port`, `redir-port`, `tproxy-port`, `allow-lan`, `bind-address`, `mode`, `log-level`, `ipv6`, `tcp-concurrent`, `find-process-mode`, `unified-delay`, `inbound-tfo`, `inbound-mptcp` | none; the app builds listeners from its own inbound settings |
| authentication | `authentication`, `skip-auth-prefixes`, `lan-allowed-ips`, `lan-disallowed-ips` | none |
| interface | `interface-name`, `routing-mark` | none |
| external API | `external-controller`, `external-controller-tls`, `external-controller-cors`, `external-controller-unix`, `external-controller-pipe`, `external-controller-routing-mark`, `external-doh-server`, `secret`, `external-ui`, `external-ui-name`, `external-ui-url` | `clash_api_port` reaches the core as sing-box `experimental.clash_api.external_controller`, section 8; everything else has no field |
| geo | `geox-url`, `geo-auto-update`, `geo-update-interval`, `geodata-mode`, `geodata-loader`, `geosite-matcher` | none |
| misc | `global-ua`, `global-client-fingerprint`, `etag-support`, `keep-alive-idle`, `keep-alive-interval`, `disable-keep-alive` | none |
| TLS inbound | `tls` (`certificate`, `private-key`, `client-auth-type`, `client-auth-cert`, `ech-key`, `custom-trust-cert`) | none |
| hosts | `hosts` | none; the builder has its own hosts map |
| profile cache | `profile.store-selected`, `profile.store-fake-ip` | none |
| TUN | `tun.*` | none |
| sniffer | `sniffer.*` | none; the builder sets its own `sniff` flag per inbound |
| DNS | `dns.*` | none; the builder emits sing-box DNS from the stored `DnsSetting` |
| tunnels, listeners | `tunnels`, `listeners` | none |
| proxies | `proxies` | one entry per conversion, section 2 |
| providers, groups, rules | `proxy-providers`, `proxy-groups`, `rule-providers`, `rules`, `sub-rules` | none; routing comes from the stored `RoutingRule` rows |
| experimental | `experimental` (`quic-go-disable-gso`, `sniffer-tls-conn`, ...) | none |
| protocol servers | `vmess-config`, `ss-config`, `tuic-server` | none; these configure mihomo's own inbounds |
| NTP, iptables, Android | `ntp`, `iptables`, `clash-for-android` | none |

That list is every `yaml:` tag of `RawConfig` in `thirdparty/mihomo/config/config.go`, so a key absent from it is not a mihomo top-level key at all.

mihomo semantics a reader may need while reading a mixin: `mode` accepts `rule`, `global` and `direct`; `log-level` accepts `silent`, `error`, `warning`, `info` and `debug` (`log/level.go`); group types are `select`, `url-test`, `fallback`, `load-balance` and `relay` (`adapter/outboundgroup/parser.go`); provider types are `http`, `file` and `inline` (`adapter/provider/parser.go`); rule providers take the behaviours `domain`, `ipcidr` and `classical` over the formats `yaml` (also the default for an absent key), `text` and `mrs` (`constant/provider/interface.go`); and `profile.store-selected` with `store-fake-ip` persist in a bbolt file named `cache.db` under mihomo's home directory (`$HOME/.config/mihomo` on Unix, `constant/path.go`). None of that is interpreted here.

## 8. The Clash API

Only the sing-box build exposes the Clash API: `clash_api_enabled` is set to `runtime_core == CoreType::SingBox` in `crates/leas/src/ops/connect.rs`, and the builder then writes

```json
{"experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}}}
```

The port comes from the settings `clash_api_port`, falling back to `CLASH_API_PORT` (9090, the same value as `StatisticsConfig::clash_api_port`'s default). The app reads that API for the traffic graph: it polls `http://127.0.0.1:<port>/traffic` and consumes the streaming JSON lines. The xray path uses the gRPC stats API instead, and the native path has neither. The TUI proxy-group, connection and provider views of that API are not implemented.

## 9. Round-trip expectations

The per-type `clash_roundtrip_from_url_via_proto` tests pin the conversions that go URL to config, config to Clash, and Clash to config again, for vless, vmess, trojan, ss, ssr, socks5, http, tuic, hysteria, hysteria2, wireguard, naive, anytls, shadowtls. The h2 cases (`clash_roundtrip_via_proto_h2_keeps_config_host_free` in vmess and vless) pin that the endpoint host never lands in `h2-opts.host`. Tor, ssh and tailscale have no URL form, so their round trip is Clash to config only.

A round trip is lossy exactly where the tables above say so: `alpn` keeps the first element, `h2-opts.host` keeps the first element, `mux` collapses to a bool, `up`/`down` only survive when numeric, `ip` loses its prefix, `xhttp`, `quic` and `httpupgrade` transports export as TCP, and `fingerprint` is dropped for vless, tuic and the QUIC protocols.
