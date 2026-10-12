# Protocol Configuration Reference

> **Audience**: Developers working on import/export, config generation, or adding new protocols.
> **Status**: Living document — update when adding protocol fields or fixing precision gaps.

---

## Table of Contents

1. [Protocol Coverage](#1-protocol-coverage)
2. [VMess (`vmess://`)](#2-vmess-vmess)
3. [VLESS (`vless://`)](#3-vless-vless)
4. [Trojan (`trojan://`)](#4-trojan-trojan)
5. [Shadowsocks (`ss://`)](#5-shadowsocks-ss)
6. [ShadowsocksR (`ssr://`)](#6-shadowsocksr-ssr)
7. [SOCKS5 (`socks://`)](#7-socks5-socks)
8. [HTTP (`http://`)](#8-http-http)
9. [TUIC (`tuic://`)](#9-tuic-tuic)
10. [Hysteria2 (`hysteria2://` / `hy2://`)](#10-hysteria2-hysteria2--hy2)
11. [Hysteria v1 (`hysteria://` / `hy://`)](#11-hysteria-v1-hysteria--hy)
12. [WireGuard (`wireguard://`)](#12-wireguard-wireguard)
13. [Naïve (`naive+https://`)](#13-naïve-naivehttps)
14. [AnyTLS (`anytls://`)](#14-anytls-anytls)
15. [ShadowTLS (`shadowtls://`)](#15-shadowtls-shadowtls)
16. [Tor](#16-tor)
17. [SSH](#17-ssh)
18. [Tailscale](#18-tailscale)
19. [Inbound-Only Protocols](#19-inbound-only-protocols-redirect-tproxy-mixed)
20. [Transport Configuration](#20-transport-configuration)
21. [TLS / Security Configuration](#21-tls--security-configuration)
22. [Internal / Infrastructure Protocols](#22-internal--infrastructure-protocols)
23. [Precision Notes & Known Gaps](#23-precision-notes--known-gaps)

---

## 1. Protocol Coverage

### Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Full config type in `proto_spec`, share URL parse/reconstruct |
| ⚠️ | Placeholder (blob-only, no typed struct) |
| ❌ | Not implemented |
| — | Not applicable (inbound-only / infra) |

### Matrix

| # | Protocol | proto_spec | xray-core | sing-box | mihomo | quirktiva | Share URL | URL Format |
|---|----------|-----------|-----------|----------|--------|-----------|-----------|------------|
| 1 | VMess | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `vmess://base64(JSON)` |
| 2 | VLESS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `vless://uuid@host:port?query` |
| 3 | Trojan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `trojan://pass@host:port?query` |
| 4 | Shadowsocks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `ss://base64(method:pass)@host:port?query` |
| 5 | ShadowsocksR | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | `ssr://base64(host:port:proto:method:obfs:pass/?params)` |
| 6 | SOCKS5 | ⚠️ Placeholder | ✅ | ✅ | ✅ | ✅ | ✅ | `socks://user:pass@host:port` |
| 7 | HTTP | ⚠️ Placeholder | ✅ | ✅ | ✅ | ✅ | ✅ | `http://user:pass@host:port` |
| 8 | TUIC | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | `tuic://uuid:pass@host:port?query` |
| 9 | Hysteria2 | ✅ | ⚠️ h2 only | ✅ | ✅ | ✅ | ✅ | `hysteria2://auth@host:port?query` |
| 10 | Hysteria v1 | ⚠️ Placeholder | ✅ | ✅ | ✅ | ❌ | ✅ | `hysteria://host:port?query` |
| 11 | WireGuard | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `wireguard://key@host:port?query` |
| 12 | Naïve | ⚠️ Placeholder | ❌ | ✅ | ❌ | ❌ | ✅ | `naive+https://user:pass@host:port` |
| 13 | AnyTLS | ⚠️ Placeholder | ❌ | ✅ | ✅ | ✅ | ✅ | `anytls://host:port?query` |
| 14 | ShadowTLS | ⚠️ Placeholder | ❌ | ✅ | ❌ | ❌ | ✅ | `shadowtls://host:port?query` |
| 15 | Tor | ⚠️ Placeholder | ❌ | ✅ | ❌ | ❌ | ❌ | JSON only |
| 16 | SSH | ⚠️ Placeholder | ❌ | ✅ | ✅ | ❌ | ❌ | JSON only |
| 17 | Tailscale | ⚠️ Placeholder | ❌ | ✅ | ✅ | ❌ | ❌ | JSON only |
| 18 | Redirect | ⚠️ Placeholder | ✅ | ✅ | ❌ | ❌ | ❌ | Inbound only |
| 19 | TProxy | ⚠️ Placeholder | ✅ | ✅ | ❌ | ❌ | ❌ | Inbound only |
| 20 | Mixed | ⚠️ Placeholder | ✅ | ✅ | ❌ | ❌ | ❌ | Inbound only |

---

## 2. VMess (`vmess://`)

**Source**: `crates/leas-proto/src/proto_spec/vmess.rs` — `VmessConfig` struct

**Share URL format**: `vmess://<base64url_no_pad(JSON)>`

The base64-decoded payload is a JSON object with abbreviated 2–3 char v2rayN `VmessQRCode` keys.

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `uuid` | `id` | `String` | ✅ | — | User UUID v4 |
| `host` | `add` | `HostSpec` | ✅ | — | Server address (IP or domain) |
| `port` | `port` | `u16` | ✅ | — | Server port (string or number) |
| `security.tls` | `tls` | `Option<TlsConfig>` | ❌ | `None` | TLS config: `"tls"` or absent |
| `security.enc` | `scy` | `Option<TinyText>` | ❌ | `"auto"` | Encryption: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero` |
| `transport` | `net` | `TransportConfig` | ❌ | `Tcp` | Transport: `tcp`, `ws`, `kcp`, `grpc`, `http`/`h2`, `quic`, `httpupgrade`, `splithttp`/`xhttp` |
| `alter_id` | `aid` | `Option<TinyText>` | ❌ | `None` | Additional IDs (must be 0 for AEAD-only) |
| `path` | `path` | `Option<TinyText>` | ❌ | `None` | WS path / gRPC serviceName / KCP seed |
| `host` (transport) | `host` | `Option<String>` | ❌ | `None` | WS/HTTP host header / gRPC authority |
| — | `type` | — | ❌ | — | XHttp/SplitHTTP mode (stored in `transport.xhttp.mode`) |
| — | `v` | — | ❌ | — | Config version (not stored, always `"2"`) |

### TLS sub-parameters (in `security.tls` = `TlsConfig::Tls`)

| Field | URL Key | Type | Description |
|-------|---------|------|-------------|
| `sni` | `sni` | `Option<TinyText>` | TLS SNI override |
| `alpn` | `alpn` | `Option<TinyText>` | ALPN (comma-separated) |
| `fp` | `fp` | `Option<TinyText>` | uTLS Client Hello fingerprint |
| `insecure` | `insecure` | `Option<bool>` | Skip TLS cert verification (`1`/`true`) |

### Notes

- The `host` field serves dual role: server address (`add`) and transport host header (`host`)
- `host` starting with `/` is treated as path when `path` is empty (v2rayN compat)
- `type` field is only used for XHttp mode; ignored for other transports
- Fields not stored but round-tripped via base64 JSON: `v` (version, always "2")

### Upstream References

- Xray-core: `proxy/vmess/account.proto`, `proxy/vmess/outbound/config.proto`
- v2rayN: `ServiceLib/Models/Dto/VmessQRCode.cs`
- sing-box: `option/vmess.go` — `VMessOutboundOptions`
- mihomo: `adapter/outbound/vmess.go` — `VmessOption`

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| JSON serde round-trip | ✅ Tested |
| Full field round-trip | ✅ All fields preserved |
| Legacy bridge precision | ✅ `convert_spec_blob` maps all fields |

---

## 3. VLESS (`vless://`)

**Source**: `crates/leas-proto/src/proto_spec/vless.rs` — `VlessConfig` struct

**Share URL format**: `vless://<uuid>@<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `uuid` | (userinfo) | `String` | ✅ | — | User UUID v4 |
| `uuid_origin` | (userinfo) | `Option<TinyText>` | ❌ | `None` | Original non-UUID string (v5-derived UUID) |
| `host` | (host) | `HostSpec` | ✅ | — | Server address |
| `port` | (port) | `u16` | ✅ | — | Server port |
| `security` | `security` | `SecurityConfig` | ❌ | `none` | TLS mode: `none`, `tls`, `reality` |
| `encryption` | `encryption` | `Option<TinyText>` | ❌ | `none` | Payload encryption (typically `none`) |
| `flow` | `flow` | `Option<TinyText>` | ❌ | `None` | XTLS flow: `xtls-rprx-vision`, `xtls-rprx-vision-udp443` |
| `transport` | `type` | `TransportConfig` | ❌ | `tcp` | Transport type |
| `path` | `path` | `Option<TinyText>` | ❌ | `None` | WS/gRPC path |
| `splice` | `splice` | `Option<bool>` | ❌ | `None` | Splice mode (`1`/`0`, `true`/`false`) |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### TLS sub-parameters

| Mode | URL Key | Type | Description |
|------|---------|------|-------------|
| `tls` | `sni` | `Option<TinyText>` | TLS SNI override |
| `tls` | `alpn` | `Option<TinyText>` | ALPN list |
| `tls` | `fp` | `Option<TinyText>` | uTLS fingerprint |
| `tls` | `allowInsecure` / `allow_insecure` / `allowinsecure` / `skipVerify` | `Option<bool>` | Skip verification |
| `reality` | `sni` | `Option<TinyText>` | REALITY SNI |
| `reality` | `fp` | `Option<TinyText>` | uTLS fingerprint |
| `reality` | `pbk` | `Option<String>` | REALITY public key |
| `reality` | `sid` | `Option<TinyText>` | REALITY short ID |
| `reality` | `spx` | `Option<TinyText>` | REALITY spider X |

### Transport sub-parameters

| Transport | URL Keys | Notes |
|-----------|----------|-------|
| `xhttp` | `mode`, `extra` | Mode: `auto`, `packet-up`, `stream-up`, `stream-one`; extra: JSON blob |
| `httpupgrade` | `host` | HTTP Host header |
| Any non-TCP | `host` | Transport host header |
| Any | `path` | Shared path field |

### Notes

- Userinfo may be a short string (not a UUID) → v5-generated from nil namespace, stored in `uuid_origin`
- REALITY is VLESS-only (not supported by VMess)
- `security` defaults to `"none"` (unlike Trojan which defaults to `"tls"`)
- For `type=grpc`, path is also accepted as `serviceName` query param

### Upstream References

- Xray-core: `proxy/vless/account.proto`, `proxy/vless/outbound/config.proto`
- sing-box: `option/vless.go` — `VLESSOutboundOptions`
- v2rayN: `VLESSFmt.cs`
- mihomo: `adapter/outbound/vless.go` — `VlessOption`

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested (multiple variants) |
| JSON serde round-trip | ✅ Tested |
| `uuid_origin` preservation | ✅ Tested |
| XHttp mode recovery | ✅ Tested |
| Reality config | ✅ Tested |

---

## 4. Trojan (`trojan://`)

**Source**: `crates/leas-proto/src/proto_spec/trojan.rs` — `TrojanConfig` struct

**Share URL format**: `trojan://<password>@<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `password` | (userinfo) | `String` | ✅ | — | Trojan password |
| `host` | (host) | `HostSpec` | ✅ | — | Server address |
| `port` | (port) | `u16` | ✅ | — | Server port |
| `security` | `security` | `SecurityConfig` | ❌ | `tls` | TLS mode: `tls`, `none`, `reality` |
| `transport` | `type` | `TransportConfig` | ❌ | `tcp` | Transport type |
| `path` | `path` | `Option<TinyText>` | ❌ | `None` | WS/gRPC path |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### TLS sub-parameters

Same as VLESS TLS (`sni`, `alpn`, `fp`, `allowInsecure` aliases, plus `reality` mode).

### Notes

- Security defaults to `"tls"` (not `"none"` — Trojan always uses TLS by default)
- `allowInsecure` accepts 4 aliases: `allowInsecure`, `allow_insecure`, `allowinsecure`, `skipVerify`
- `sni` fallback chain: `peer` query param → `sni` → URL hostname
- Legacy format: `ws=1` + `wspath=` instead of `type=ws` + `path=`
- Wire protocol uses SHA-224(password) → 56-byte hex for auth

### Upstream References

- trojan-gfw C++: `src/core/config.h`
- Xray-core: `proxy/trojan/protocol.go`, `proxy/trojan/config.proto`
- sing-box: `option/trojan.go` — `TrojanOutboundOptions`
- mihomo: `adapter/outbound/trojan.go` — `TrojanOption`

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| `security=none` | ✅ Tested |
| TLS + WS transport | ✅ Tested |
| JSON serde round-trip | ✅ Tested |

---

## 5. Shadowsocks (`ss://`)

**Source**: `crates/leas-proto/src/proto_spec/ss.rs` — `SsConfig` struct

**Share URL format (SIP002)**: `ss://<base64url_no_pad(method:password)>@<host>:<port>#<remarks>?plugin=...`

Also accepts:
- Legacy QR: `ss://<base64(method:password@host:port)>`
- Plain: `ss://method:password@host:port`

### Parameters

| Field | Source | Type | Required | Default | Description |
|-------|--------|------|----------|---------|-------------|
| `method` | userinfo | `TinyText` | ✅ | — | Encryption cipher |
| `password` | userinfo | `String` | ✅ | — | Shared secret |
| `host` | hostport | `HostSpec` | ✅ | — | Server address |
| `port` | hostport | `u16` | ✅ | `8388` | Server port |
| ~~`plugin`~~ | query `plugin` | — | ❌ | — | **NOT STORED** — precision gap |
| ~~`plugin_opts`~~ | query `plugin_opts` | — | ❌ | — | **NOT STORED** — precision gap |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### Valid Ciphers

- **Legacy**: `rc4-md5`, `aes-256-cfb`, `aes-128-cfb`, `chacha20`, `salsa20`, `bf-cfb`, `des-cfb`, `camellia-128-cfb`, `camellia-256-cfb`
- **AEAD**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`
- **AEAD-2022**: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`

### ⚠️ Precision Gap

`SsConfig` **lacks `plugin` and `plugin_opts` fields**. SIP003 plugins (simple-obfs, v2ray-plugin, etc.) are parsed by `import_export.rs` into the legacy JSON blob but are NOT stored in the typed struct. On proto_spec round-trip (parse → reconstruct), plugin config is silently dropped.

**Workaround**: Use the legacy `import_export.rs` path (`parse_share_url`/`format_share_url`) which preserves plugin in the JSON blob bridge.

**Fix**: Add `plugin: Option<TinyText>` + `plugin_opts: Option<TinyText>` to `SsConfig`, wire into `try_parse`/`reconstruct`.

### Upstream References

- shadowsocks-rust: `src/config.rs` SIP002 `from_url()`/`to_url()`
- SIP002 spec: <https://github.com/shadowsocks/shadowsocks-org/issues/27>
- sing-box: `option/shadowsocks.go` — `ShadowsocksOutboundOptions` (has `Plugin`/`PluginOptions`)
- mihomo: `adapter/outbound/shadowsocks.go` — `ShadowSocksOption` (has `Plugin`/`PluginOpts`)

### Round-Trip Precision

| Check | Status |
|-------|--------|
| Basic parse → reconstruct | ✅ Tested |
| Remarks preservation | ✅ Tested |
| **Plugin round-trip** | ❌ **LOST — not in struct** |
| AEAD-2022 ciphers | ✅ Handled (method string only) |
| Legacy QR format | ✅ Accepted |
| JSON serde round-trip | ✅ Tested |

---

## 6. ShadowsocksR (`ssr://`)

**Source**: `crates/leas-proto/src/proto_spec/ssr.rs` — `SsrConfig` struct

**Share URL format**: `ssr://<base64url(host:port:protocol:method:obfs:base64(password)/?params)>`

### Parameters

| Field | Position | Type | Required | Description |
|-------|----------|------|----------|-------------|
| `host` | 1 | `HostSpec` | ✅ | Server address |
| `port` | 2 | `u16` | ✅ | Server port |
| `protocol` | 3 | `TinyText` | ✅ | Protocol plugin (`origin`, `auth_aes128_md5`, etc.) |
| `method` | 4 | `TinyText` | ✅ | Encryption cipher |
| `obfs` | 5 | `TinyText` | ✅ | Obfuscation plugin (`plain`, `http_simple`, etc.) |
| `password` | 6 (base64) | `String` | ✅ | Shared secret |

### Query Parameters (stored in `params` HashMap)

| Key | Encoding | Type | Description |
|-----|----------|------|-------------|
| `group` | base64 | `String` | Provider/group name |
| `remarks` | base64 | `String` | Node name (mapped to `self.remarks`) |
| `obfsparam` | base64 | `String` | Obfuscation parameter |
| `protoparam` | base64 | `String` | Protocol parameter |

### Notes

- Port is last-5th colon-delimited field (handles IPv6 with multiple colons)
- Password may contain `/?` or `?` split for query params
- Trailing non-base64 garbage (Telegram annotation) is stripped before decode
- `obfsparam` and `protoparam` stored in generic `HashMap` — strongly-typed access lost but round-trip preserved

### Upstream References

- sing-box: `option/shadowsocksr.go` — `ShadowsocksROutboundOptions` (typed `ObfsParam`/`ProtocolParam`)
- subconverter: `subparser.cpp` `explodeSSR()`
- mihomo: `adapter/outbound/shadowsocksr.go` — `ShadowSocksROption`

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| Generic params round-trip | ✅ (HashMap preserves key ordering) |

---

## 7. SOCKS5 (`socks://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `socks://<user:pass@><host>:<port>#<remarks>`

### Parameters

| Field | Source | Type | Required | Default | Description |
|-------|--------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `1080` | Server port |
| `username` | userinfo | `String` | ❌ | — | SOCKS5 username |
| `password` | userinfo | `String` | ❌ | — | SOCKS5 password |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only. All fields preserved via legacy bridge.

### Upstream References

- sing-box: `option/simple.go` — `SOCKSOutboundOptions` (adds `Version`, `Network`, `UDPOverTCP`)
- mihomo: `adapter/outbound/socks5.go` — `Socks5Option`
- Xray-core: `proxy/socks/config.proto`

---

## 8. HTTP (`http://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `http://<user:pass@><host>:<port>#<remarks>`

### Parameters

| Field | Source | Type | Required | Default | Description |
|-------|--------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `80` | Server port |
| `username` | userinfo | `String` | ❌ | — | HTTP basic auth username |
| `password` | userinfo | `String` | ❌ | — | HTTP basic auth password |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only.

### Upstream References

- sing-box: `option/simple.go` — `HTTPOutboundOptions` (adds TLS, Path, Headers)
- mihomo: `adapter/outbound/http.go` — `HttpOption`
- Xray-core: `proxy/http/config.proto`

---

## 9. TUIC (`tuic://`)

**Source**: `crates/leas-proto/src/proto_spec/tuic.rs` — `TuicConfig` struct

**Share URL format**: `tuic://<uuid:password>@<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `uuid` | userinfo | `String` | ✅ | — | User UUID |
| `password` | userinfo | `String` | ✅ | — | Authentication password |
| `host` | hostport | `HostSpec` | ✅ | — | Server address |
| `port` | hostport | `u16` | ✅ | — | Server port |
| `congestion_control` | `congestion_control` | `Option<TinyText>` | ❌ | `bbr` | CC: `cubic`, `bbr`, `new_reno`, `bbr3` |
| `udp_relay_mode` | `udp_relay_mode` | `Option<TinyText>` | ❌ | `native` | UDP: `native`, `quic` |
| `security` | TLS params | `SecurityConfig` | ❌ | TLS always | Always TLS-based |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### TLS sub-parameters

| URL Key | Type | Description |
|---------|------|-------------|
| `sni` | `Option<TinyText>` | TLS SNI override |
| `alpn` | `Option<TinyText>` | ALPN (typically `h3`) |
| `allow_insecure` / `insecure` / `allowInsecure` | `Option<bool>` | Skip verification |

### Notes

- TUIC always uses TLS (QUIC-based)
- Default congestion control is `bbr` (sing-box) / `cubic` (mihomo)
- sing-box also supports `udp_over_stream`, `zero_rtt_handshake`, `heartbeat` — not in standard share URLs

### Upstream References

- sing-box: `option/tuic.go` — `TUICOutboundOptions` (adds `ZeroRTTHandshake`, `UDPOverStream`, `Heartbeat`)
- mihomo: `adapter/outbound/tuic.go` — `TuicOption` (adds extensive QUIC tuning params)

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| Congestion control | ✅ Preserved |
| Allow-insecure | ✅ Preserved |
| Remarks | ✅ Preserved |
| JSON serde round-trip | ✅ Tested |

---

## 10. Hysteria2 (`hysteria2://` / `hy2://`)

**Source**: `crates/leas-proto/src/proto_spec/hysteria2.rs` — `Hysteria2Config` struct

**Share URL format**: `hysteria2://<auth>@<host>:<port>/?<query_params>#<remarks>`

Accepts both `hysteria2://` and `hy2://` schemes.

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `auth` | userinfo | `String` | ✅ | — | Authentication token/password |
| `host` | hostport | `HostSpec` | ✅ | — | Server address |
| `port` | hostport | `PortSpec` | ✅ | `443` | Port (supports `:443,7788-8899` hopping) |
| `obfs` | `obfs` | `Option<TinyText>` | ❌ | `None` | Obfuscation type (e.g., `salamander`) |
| `obfs_password` | `obfs-password` | `Option<TinyText>` | ❌ | `None` | Obfuscation pre-shared key |
| `up` | `up` | `Option<TinyText>` | ❌ | `None` | Upload bandwidth limit (string Mbps) |
| `down` | `down` | `Option<TinyText>` | ❌ | `None` | Download bandwidth limit (string Mbps) |
| `security` | TLS params | `SecurityConfig` | ❌ | TLS always | Always TLS-based (QUIC) |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### TLS sub-parameters

| URL Key | Type | Description |
|---------|------|-------------|
| `sni` | `Option<TinyText>` | TLS SNI override |
| `insecure` | `Option<bool>` | Skip verification (`1`/`true`/`yes`) |

### Notes

- Port supports extended syntax: single (`:443`), list (`:443,7788,9999`), range (`:8888-9999`), mixed
- Auth can be single token or `user:pass` pair (concatenated)
- Default port is 443
- Salamander obfuscation uses BLAKE2b-256 with 8-byte random salt
- `up`/`down` stored as raw string — config builder must parse to Mbps int for sing-box JSON

### Upstream References

- Hysteria2: `app/cmd/client.go` `parseURI()`, `app/internal/url/url.go`
- sing-box: `option/hysteria2.go` — `Hysteria2OutboundOptions` (adds `ServerPorts`, `HopInterval`, `BrutalDebug`, bandwidth as `int` Mbps)
- mihomo: `adapter/outbound/hysteria2.go` — `Hysteria2Option` (adds extensive QUIC tuning)

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| Obfs + obfs-password | ✅ Preserved |
| Port hopping | ✅ Preserved (PortSpec) |
| JSON serde round-trip | ✅ Tested |

---

## 11. Hysteria v1 (`hysteria://` / `hy://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `hysteria://<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `443` | Server port |
| `protocol` | `protocol` / `type` | `String` | ❌ | — | Protocol variant |
| `auth` | `auth` | `String` | ❌ | — | Authentication token |
| `obfs` | `obfs` | `String` | ❌ | — | Obfuscation (`faketcp`) |
| `up_mbps` | `upmbps` / `up_mbps` | `i64` | ❌ | `100` | Upload bandwidth limit (Mbps) |
| `down_mbps` | `downmbps` / `down_mbps` | `i64` | ❌ | `100` | Download bandwidth limit (Mbps) |
| `sni` | `sni` | `String` | ❌ | — | TLS SNI |
| `insecure` | `insecure` | `bool` | ❌ | `false` | Skip TLS verification |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only.

### Upstream References

- sing-box: `option/hysteria.go` — `HysteriaOutboundOptions` (adds `ReceiveWindowConn`, `ReceiveWindow`, `DisableMTUDiscovery`)

---

## 12. WireGuard (`wireguard://`)

**Source**: `crates/leas-proto/src/proto_spec/wireguard.rs` — `WireguardConfig` struct

**Share URL format**: `wireguard://<percent-encoded(private_key)>@<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `private_key` | userinfo | `String` | ✅ | — | Private key (percent-encoded) |
| `host` | hostport | `HostSpec` | ✅ | — | Endpoint address |
| `port` | hostport | `u16` | ✅ | `2408` | Endpoint port |
| `address` | `address` | `TinyText` | ✅ | — | Interface address (CIDR, e.g. `10.0.0.2/32`) |
| `public_key` | `publickey` / `public_key` | `String` | ✅ | — | Peer's public key (base64) |
| `preshared_key` | `presharedkey` / `psk` | `Option<String>` | ❌ | — | Pre-shared key (base64) |
| `reserved` | `reserved` | `Option<TinyText>` | ❌ | — | Reserved bytes (3 comma-separated or base64) |
| `mtu` | `mtu` | `Option<TinyText>` | ❌ | `1420` | Interface MTU |
| `remarks` | `#` fragment | `Option<TinyText>` | ❌ | `None` | Display name |

### Notes

- Default MTU: 1420 (Xray-core), 1280 (WireGuard-go)
- Default port: 2408 (v2rayN), 51820 (WireGuard native)
- Single-peer model — sing-box supports multi-peer (`Peers[]` with `AllowedIPs`, `PersistentKeepaliveInterval`)
- `reserved` accepts both comma-separated decimals and base64-encoded bytes

### Upstream References

- sing-box: `option/wireguard.go` — `WireGuardEndpointOptions` + `WireGuardPeer` (multi-peer)
- Xray-core: `proxy/wireguard/config.proto` — `DeviceConfig`
- mihomo: `adapter/outbound/wireguard.go` — `WireGuardOption`

### Round-Trip Precision

| Check | Status |
|-------|--------|
| parse → reconstruct → parse | ✅ Tested |
| Full params (mtu, reserved, preshared) | ✅ Tested |
| Remarks with `@` prefix | ✅ Tested |
| JSON serde round-trip | ✅ Tested |

---

## 13. Naïve (`naive+https://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `naive+https://<user:pass@><host>:<port>#<remarks>`

### Parameters

| Field | Source | Type | Required | Default | Description |
|-------|--------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `443` | Server port |
| `username` | userinfo | `String` | ❌ | — | Basic auth username |
| `password` | userinfo | `String` | ❌ | — | Basic auth password |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only.

### Upstream References

- sing-box: `option/naive.go` — `NaiveOutboundOptions` (adds `InsecureConcurrency`, `ExtraHeaders`, QUIC tuning, `UDPOverTCP`)

---

## 14. AnyTLS (`anytls://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `anytls://<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `443` | Server port |
| `password` | `password` / `auth` | `String` | ❌ | — | Authentication password |
| `sni` | `sni` | `String` | ❌ | — | TLS SNI |
| `alpn` | `alpn` | `String` | ❌ | — | ALPN |
| `insecure` | `insecure` / `allow_insecure` | `bool` | ❌ | `false` | Skip verification |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only.

### Upstream References

- sing-box: `option/anytls.go` — `AnyTLSOutboundOptions` (adds `IdleSessionCheckInterval`, `IdleSessionTimeout`, `MinIdleSession`)
- mihomo: `adapter/outbound/anytls.go` — `AnyTLSOption`
- quirktiva: `adapter/outbound/anytls.go` — `AnyTLSOption`

---

## 15. ShadowTLS (`shadowtls://`)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: `shadowtls://<host>:<port>?<query_params>#<remarks>`

### Parameters

| Field | URL Key | Type | Required | Default | Description |
|-------|---------|------|----------|---------|-------------|
| `host` | hostport | `String` | ✅ | — | Server address |
| `port` | hostport | `u16` | ❌ | `443` | Server port |
| `password` | `password` | `String` | ❌ | — | ShadowTLS password |
| `version` | `version` | `String` | ❌ | — | Protocol version |
| `sni` | `sni` | `String` | ❌ | — | TLS SNI |
| `remarks` | `#` fragment | `Option<String>` | ❌ | `None` | Display name |

### Precision Status

**⚠️ Placeholder** — no typed struct. Round-trips through legacy JSON blob only.

### Upstream References

- sing-box: `option/shadowtls.go` — `ShadowTLSOutboundOptions` (adds `Version`, `Password`)
- `thirdparty/sing-box/docs/configuration/outbound/shadowtls.md`

---

## 16. Tor

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: None — JSON config only.

### Parameters (sing-box `TorOutboundOptions`)

| Field | Type | Description |
|-------|------|-------------|
| `executable_path` | `string` | Tor binary path |
| `extra_args` | `[]string` | Extra CLI arguments |
| `data_directory` | `string` | Tor data directory |
| `torrc` | `map[string]string` | Additional torrc options |

### Precision Status

**⚠️ Placeholder** — no share URL format exists in any upstream. Only configurable via JSON config file or UI form.

---

## 17. SSH

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: None — JSON config only.

### Parameters (sing-box `SSHOutboundOptions`)

| Field | Type | Description |
|-------|------|-------------|
| `user` | `string` | SSH username |
| `password` | `string` | SSH password |
| `private_key` | `listable[string]` | SSH private key(s) |
| `private_key_path` | `string` | SSH private key path |
| `private_key_passphrase` | `string` | SSH private key passphrase |
| `host_key` | `listable[string]` | Accepted host keys |
| `host_key_algorithms` | `listable[string]` | Host key algorithms |
| `client_version` | `string` | SSH client version string |

### Precision Status

**⚠️ Placeholder** — no standard share URL format. Configurable via JSON or UI form.

---

## 18. Tailscale

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: None — JSON config only.

### Parameters (sing-box `TailscaleEndpointOptions`)

| Field | Type | Description |
|-------|------|-------------|
| `state_directory` | `string` | Tailscale state directory |
| `auth_key` | `string` | Auth key for node registration |
| `control_url` | `string` | Control server URL |
| `ephemeral` | `bool` | Ephemeral node |
| `hostname` | `string` | Node hostname |
| `accept_routes` | `bool` | Accept advertised routes |
| `exit_node` | `string` | Exit node |
| `exit_node_allow_lan_access` | `bool` | Allow LAN while using exit node |
| `advertise_routes` | `[]netip.Prefix` | Routes to advertise |
| `advertise_exit_node` | `bool` | Advertise as exit node |
| `advertise_tags` | `[]string` | Tags for the node |
| `relay_server_port` | `*uint16` | DERP relay server port |
| `system_interface` | `bool` | Use system interface |
| `udp_timeout` | `Duration` | UDP session timeout |

### Precision Status

**⚠️ Placeholder** — no standard share URL format. Configurable via JSON or UI form.

---

## 19. Inbound-Only Protocols (Redirect, TProxy, Mixed)

**Source**: `crates/leas-proto/src/proto_spec/mod.rs` — `PlaceholderConfig` (stub)

**Share URL format**: None — inbound/proxy types, not used as outbound destinations.

| Protocol | xray-core | sing-box | mihomo | Description |
|----------|-----------|----------|--------|-------------|
| Redirect | ✅ Redirect outbound | ✅ `TypeRedirect` | ❌ | Redirect traffic to a port |
| TProxy | ✅ TProxy outbound | ✅ `TypeTProxy` | ❌ | Transparent proxy |
| Mixed | ✅ Mixed inbound | ✅ `TypeMixed` | ❌ | SOCKS + HTTP on one port |

These are inbound/listener types in most architectures. The outbound versions exist in xray-core but are typically not used as share URL targets.

### Precision Status

**⚠️ Placeholder** — acceptable, these are rarely used as outbound proxy destinations.

---

## 20. Transport Configuration

**Source**: `crates/leas-proto/src/proto_spec/common.rs` — `TransportConfig` enum

### Transport Types

| Variant | Type String | VMess `net=` | VLESS/Trojan `type=` | Description |
|---------|-------------|--------------|----------------------|-------------|
| `Tcp` | `tcp` | `tcp` | `tcp` | Raw TCP |
| `Ws(WebSocketConfig)` | `ws` | `ws`/`websocket` | `ws`/`websocket` | WebSocket tunnel |
| `Grpc(GrpcConfig)` | `grpc` | `grpc` | `grpc` | gRPC tunnel |
| `Http(HttpConfig)` | `http` | `http`/`h2`/`https` | `http`/`h2`/`https` | HTTP/2 tunnel |
| `Quic` | `quic` | `quic` | `quic` | QUIC tunnel |
| `Kcp(KcpConfig)` | `kcp` | `kcp`/`mkcp` | `kcp`/`mkcp` | mKCP tunnel (Xray-only) |
| `HttpUpgrade(HttpUpgradeConfig)` | `httpupgrade` | `httpupgrade` | `httpupgrade` | HTTPUpgrade (fake WS) |
| `XHttp(XHttpConfig)` | `xhttp` | `splithttp`/`xhttp` | `splithttp`/`xhttp` | SplitHTTP/XHTTP |

### WebSocketConfig (`Ws`)

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Option<TinyText>` | WebSocket path |
| `host` | `Option<TinyText>` | HTTP Host header |
| `headers` | `Option<HashMap<String, String>>` | Additional HTTP headers |
| `max_early_data` | `Option<u32>` | Max early data size (v2fly feature) |
| `early_data_header_name` | `Option<TinyText>` | Early data header name |

### GrpcConfig (`Grpc`)

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Option<TinyText>` | gRPC service name (legacy compat) |
| `authority` | `Option<TinyText>` | `:authority` header override |
| `service_name` | `Option<TinyText>` | gRPC service name (preferred) |

### HttpConfig (`Http` / h2)

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Option<TinyText>` | HTTP/2 path |
| `host` | `Option<TinyText>` | HTTP Host header(s) |
| `method` | `Option<TinyText>` | HTTP method |
| `headers` | `Option<HashMap<String, String>>` | Additional HTTP headers |

### KcpConfig (`Kcp`)

| Field | Type | Description |
|-------|------|-------------|
| `mtu` | `Option<u32>` | KCP MTU |
| `tti` | `Option<u32>` | KCP TTI (ms) |
| `uplink_capacity` | `Option<u32>` | Uplink capacity |
| `downlink_capacity` | `Option<u32>` | Downlink capacity |
| `congestion` | `Option<bool>` | Congestion control |
| `read_buffer` | `Option<u32>` | Read buffer size |
| `write_buffer` | `Option<u32>` | Write buffer size |
| `seed` | `Option<TinyText>` | KCP seed for obfuscation |

### HttpUpgradeConfig (`HttpUpgrade`)

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Option<TinyText>` | Upgrade path |
| `host` | `Option<TinyText>` | HTTP Host header |
| `headers` | `Option<HashMap<String, String>>` | Additional headers |
| `ed` | `Option<u32>` | Early data size |

### XHttpConfig (`XHttp` / SplitHTTP)

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Option<TinyText>` | HTTP path |
| `host` | `Option<TinyText>` | HTTP Host header |
| `mode` | `Option<TinyText>` | Mode: `auto`, `packet-up`, `stream-up`, `stream-one` |
| `headers` | `Option<HashMap<String, String>>` | Additional headers |
| `extra` | `Option<Value>` | Extra JSON blob (advanced config) |

### Upstream References

- Xray-core: `transport/internet/*/config.proto` (per-transport protos)
- sing-box: `option/v2ray_transport.go` — `V2RayTransportOptions`
- mihomo: transport config structs in respective adapter files

---

## 21. TLS / Security Configuration

**Source**: `crates/leas-proto/src/proto_spec/common.rs` — `SecurityConfig`, `TlsConfig`, `TlsOpts`, `RealityOpts`

### SecurityConfig

| Field | Type | Description |
|-------|------|-------------|
| `tls` | `Option<TlsConfig>` | TLS or REALITY config |
| `enc` | `Option<TinyText>` | Encryption method (VMess `scy`) |

### TlsConfig

| Variant | Description |
|---------|-------------|
| `Tls(TlsOpts)` | Standard TLS configuration |
| `Reality(RealityOpts)` | Xray-core REALITY (VLESS only) |

### TlsOpts

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sni` | `Option<TinyText>` | — | TLS SNI (Server Name Indication) |
| `alpn` | `Option<TinyText>` | — | ALPN list (comma-separated, e.g. `h2,http/1.1`) |
| `fp` | `Option<TinyText>` | — | uTLS Client Hello fingerprint (`chrome`, `firefox`, `safari`, `random`, `randomized`) |
| `insecure` | `Option<bool>` | `None` | Skip TLS certificate verification |

### RealityOpts

| Field | Type | Description |
|-------|------|-------------|
| `sni` | `Option<TinyText>` | REALITY server name |
| `fp` | `Option<TinyText>` | uTLS fingerprint |
| `pbk` | `Option<String>` | REALITY public key (base64) |
| `sid` | `Option<TinyText>` | REALITY short ID (hex) |
| `spx` | `Option<TinyText>` | REALITY spider X (path) |

### Precision Notes

Our `TlsOpts` covers the essential share URL fields. Sing-box `OutboundTLSOptions` has ~25 fields total, but the additional ones (`min_version`, `max_version`, `cipher_suites`, `certificate`, `curve_preferences`, ECH, `utls` config) are **JSON config only** — they never appear in share URLs. No precision loss for URL round-trip.

For JSON config generation, the config builders currently use the legacy bridge and hardcoded TLS, so the extra TLS fields are a **nice-to-have** rather than a precision fix.

---

## 22. Internal / Infrastructure Protocols

These protocol types exist in the `Protocol` enum in `crates/leas-core/src/protocol.rs` but are **not** in `proto_spec` — they are internal routing types, not shareable proxy destinations.

| Protocol | xray-core | sing-box | Description |
|----------|-----------|----------|-------------|
| `Freedom` | ✅ | — | Direct outbound (no proxy) |
| `Blackhole` | ✅ | ✅ `TypeBlock` | Sink/block outbound |
| `Dns` | ✅ | ✅ `TypeDNS` | DNS outbound |
| `Loopback` | ✅ | — | Loopback to another inbound |
| `Custom` | ✅ | — | Custom plugin outbound |
| `Shadowsocks2022` | ✅ `shadowsocks_2022` | — | Separate proto in xray (handled as SS method) |
| `DokodemoDoor` | ✅ | — | Door/redirect inbound |

None of these have share URL formats. They are selected and configured internally by the TUI.

---

## 23. Precision Notes & Known Gaps

### Confirmed Precision Loss

| # | Protocol | Field | Impact | Fix Priority |
|---|----------|-------|--------|-------------|
| 1 | Shadowsocks | `plugin`, `plugin_opts` | SIP003 plugins silently dropped on proto_spec round-trip | **HIGH** — functional loss |
| 2 | ShadowsocksR | `obfsparam`, `protoparam` | Stored in generic HashMap, no typed access | LOW — round-trip preserved |
| 3 | Hysteria2 | `up`/`down` as strings | Config builder must parse to Mbps int | LOW — string parse is safe |
| 4 | All placeholder | Entire config | No typed fields, opaque JSON blob only | MEDIUM — no loss today but no validation |

### Missing Fields (JSON config only — not in share URLs)

These are fields present in upstream option structs that never appear in share URLs. They are not precision losses for URL round-trip but may be for JSON config round-trip:

| Protocol | Missing Fields | Source |
|----------|---------------|--------|
| VMess | `global_padding`, `authenticated_length`, `packet_encoding`, `network`, `multiplex` | sing-box `VMessOutboundOptions` |
| VLESS | `packet_encoding`, `network`, `multiplex` | sing-box `VLESSOutboundOptions` |
| Trojan | `network`, `multiplex` | sing-box `TrojanOutboundOptions` |
| TUIC | `udp_over_stream`, `zero_rtt_handshake`, `heartbeat`, `network` | sing-box `TUICOutboundOptions` |
| Hysteria2 | `server_ports`, `hop_interval`, `brutal_debug` | sing-box `Hysteria2OutboundOptions` |
| WireGuard | `allowed_ips`, `persistent_keepalive_interval`, `workers`, `listen_port` | sing-box `WireGuardPeer` + `WireGuardEndpointOptions` |
| All TLS | `min_version`, `max_version`, `cipher_suites`, `certificate`, `curve_preferences`, ECH, utls | sing-box `OutboundTLSOptions` |
| Transport: gRPC | `idle_timeout`, `ping_timeout`, `permit_without_stream` | sing-box `V2RayGRPCOptions` |
| Transport: http | `idle_timeout`, `ping_timeout`, host as list | sing-box `V2RayHTTPOptions` |

### Round-Trip Test Coverage

| Test | Coverage | Notes |
|------|----------|-------|
| `check_roundtrip` parse→reconstruct→parse | All 8 real configs | Tests single example per protocol |
| Multi-variant round-trip | VLESS only | VLESS tests 3 variants + XHttp + httpupgrade |
| `security=none` | Trojan only | Trojan tests explicit no-TLS round-trip |
| Serde round-trip | All 8 real configs | JSON serialize → deserialize → compare |
| Plugin round-trip | **NONE** | SS plugin not tested (gap) |
| All-fields round-trip | **NONE** | No test exercises every optional field |
| JSON config round-trip | **NONE** | No `to_json_config` → parse → compare test |
| Bridge precision | **NONE** | No `Profile` → `ProtocolConfig` → `Profile` test |

### Source Map

| Component | Path | Key Types |
|-----------|------|-----------|
| Config structs | `crates/leas-proto/src/proto_spec/*.rs` | VMess, VLESS, Trojan, SS, SSR, TUIC, H2, WG |
| Common types | `crates/leas-proto/src/proto_spec/common.rs` | TransportConfig, SecurityConfig, TlsConfig, RealityOpts |
| URL parsing | `crates/leas-proto/src/urlx/` | RawUrlX, SchemeX, HostSpec, PortSpec |
| URL utilities | `crates/leas-proto/src/proto_spec/utils.rs` | Query parsing, base64, host/port |
| Import/export | `crates/leas-config/src/import_export.rs` | All 14 protocol parsers + formatters |
| Config builders | `crates/leas-core/src/config_builder/xray.rs` | Xray JSON generation |
| Config builders | `crates/leas-core/src/config_builder/singbox.rs` | Sing-box JSON generation |
| Protocol enum | `crates/leas-core/src/protocol.rs` | `Protocol` enum + `ParseProtocolError` |
| Forms | `crates/leas-config/src/forms.rs` | TUI form field definitions |
| Core routing | `crates/leas-core/src/config_builder/mod.rs` | CoreType determination |
| Upstream: sing-box | `thirdparty/sing-box/option/*.go` | All outbound option structs |
| Upstream: mihomo | `thirdparty/mihomo/adapter/outbound/*.go` | All proxy option structs |
| Upstream: Xray-core | `thirdparty/Xray-core/proxy/*/config.proto` | All outbound config protos |
| Upstream: quirktiva | `thirdparty/quirktiva/adapter/outbound/*.go` | All proxy option structs |


## 24. URL Parsing Methods Cross-Reference

Cross-referencing all upstream projects' share URL parsing implementations against our codebase.

### 24.1 Protocol Coverage by Upstream

Clients that consume share URLs directly (v2rayN, v2rayNG, xray-checker) and converters that parse them (subconverter):

| # | Protocol | URL Scheme | v2rayN (C#) | v2rayNG (Kotlin) | subconverter (C++) | xray-checker (Go) | **Our `import_export.rs`** | **Our `proto_spec`** |
|---|----------|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | VMess | `vmess://base64(JSON)` | ✅ `VmessFmt` | ✅ `VmessFmt.kt` | ✅ `explodeVmess` | ✅ libXray | ✅ full | ✅ VmessConfig |
| 2 | VLESS | `vless://` | ✅ `VLESSFmt` | ✅ `VlessFmt.kt` | ❌ | ✅ libXray | ✅ full | ✅ VlessConfig |
| 3 | Trojan | `trojan://` | ✅ `TrojanFmt` | ✅ `TrojanFmt.kt` | ✅ `explodeTrojan` | ✅ libXray | ✅ full | ✅ TrojanConfig |
| 4 | Shadowsocks | `ss://` | ✅ `ShadowsocksFmt` | ✅ `ShadowsocksFmt.kt` | ✅ `explodeSS` | ✅ libXray | ✅ full | ✅ SsConfig ⚠️\* |
| 5 | ShadowsocksR | `ssr://` | ❌ | ❌ | ✅ `explodeSSR` | ❌ | ✅ full | ✅ SsrConfig |
| 6 | SOCKS5 | `socks://` | ✅ `SocksFmt` | ✅ `SocksFmt.kt` | ✅ `explodeSocks` | ✅ native | ✅ full | ⚠️ Placeholder |
| 7 | HTTP | `http://` | ❌ | ❌ | ✅ `explodeHTTP` | ✅ native | (bridge only) | ⚠️ Placeholder |
| 8 | TUIC | `tuic://` | ✅ `TuicFmt` | ❌ | ❌ | ❌ | ✅ full | ✅ TuicConfig |
| 9 | Hysteria2 | `hysteria2://` / `hy2://` | ✅ `Hysteria2Fmt` | ✅ `Hysteria2Fmt.kt` | ✅ `explodeHysteria2` | ✅ libXray | ✅ full | ✅ Hysteria2Config |
| 10 | Hysteria1 | `hysteria://` / `hy://` | ❌ | ❌ | ❌ | ❌ | ✅ full | ⚠️ Placeholder |
| 11 | WireGuard | `wireguard://` | ✅ `WireguardFmt` | ✅ `WireguardFmt.kt` | ❌ | ✅ native | ✅ full | ✅ WireguardConfig |
| 12 | Naïve | `naive+https://` / `naive+quic://` | ✅ `NaiveFmt` | ❌ | ❌ | ❌ | ✅ full | ⚠️ Placeholder |
| 13 | AnyTLS | `anytls://` | ✅ `AnytlsFmt` | ❌ | ✅ `explodeAnyTLS` | ❌ | ✅ full | ⚠️ Placeholder |
| 14 | ShadowTLS | `shadowtls://` | ❌ | ❌ | ❌ | ❌ | ✅ full | ⚠️ Placeholder |

> `⚠️\*` = SsConfig missing `plugin`/`plugin_opts` (confirmed precision loss).
> v2ray-core and v2ray-core-legacy have **zero** URL parsing — they are proxy runtimes, not clients.

### 24.2 Standard URL Query Parameter Vocabulary

The following parameter names are **identical across v2rayN (C# `BaseFmt`) and v2rayNG (Kotlin `FmtBase`)**.
They form the de-facto standard for v2ray-style share URLs.

#### TLS / Security (protocol-agnostic, shared by ALL v2ray-style URLs)

| URL Param | Description | Our proto_spec | v2rayN field | v2rayNG field |
|-----------|-------------|:---:|:---|:---|
| `security` | TLS mode (`tls`/`reality`/`none`) | ✅ `SecurityConfig` | `StreamSecurity` | `security` |
| `sni` | TLS SNI override | ✅ `TlsOpts.sni` | `Sni` | `sni` |
| `alpn` | ALPN list (comma-separated) | ✅ `TlsOpts.alpn` | `Alpn` | `alpn` |
| `fp` | uTLS Client Hello fingerprint | ✅ `TlsOpts.fp` | `Fingerprint` | `fingerPrint` |
| `pbk` | REALITY public key | ✅ `RealityOpts.pbk` | `PublicKey` | `publicKey` |
| `sid` | REALITY short ID (hex) | ✅ `RealityOpts.sid` | `ShortId` | `shortId` |
| `spx` | REALITY spider X (path) | ✅ `RealityOpts.spx` | `SpiderX` | `spiderX` |
| `insecure` / `allowInsecure` / `allow_insecure` | Skip TLS verification | ✅ `TlsOpts.insecure` | `AllowInsecure` | `insecure` |
| `pqv` | Post-quantum ML-DSA65 signature | ❌ **Missing** | `Mldsa65Verify` | `mldsa65Verify` |
| `ech` | Encrypted Client Hello config | ❌ **Missing** | `EchConfigList` | `echConfigList` |
| `vcn` | Verify peer cert by name | ❌ **Missing** | `VerifyPeerCertByName` | `verifyPeerCertByName` |
| `pcs` | Certificate SHA-256 fingerprint | ❌ **Missing** | `CertSha` | `pinnedCA256` |
| `fm` | Finalmask JSON blob (advanced routing) | ❌ **Missing** | `Finalmask` | `finalMask` |

#### Transport (by type)

| URL Param | Applies To | Description | Our proto_spec | v2rayN/v2rayNG |
|-----------|-----------|-------------|:---:|:---:|
| `type` | All | Transport type (tcp/kcp/ws/grpc/http/xhttp/httpupgrade) | ✅ `TransportConfig` | `Network` |
| `host` | raw/tcp, ws, http, xhttp, httpupgrade | Transport host header | ✅ per-type | `Host` |
| `path` | raw/tcp, ws, xhttp, httpupgrade, http | Transport path | ✅ per-type | `Path` |
| `headerType` | raw/tcp, kcp | TCP/KCP header obfuscation | ❌ **Missing** | `headerType` |
| `seed` | kcp | KCP seed | ✅ `KcpConfig.seed` | `seed` |
| `mtu` | kcp | KCP MTU | ✅ `KcpConfig.mtu` | `mtu` |
| `tti` | kcp | KCP TTI (ms) | ✅ `KcpConfig.tti` | `tti` |
| `mode` | grpc, xhttp | gRPC GUN/Multi mode, XHttp mode | ❌ **Missing for gRPC** | `mode` |
| `authority` | grpc | gRPC `:authority` header override | ❌ **Missing** | `authority` |
| `serviceName` | grpc | gRPC service name | ✅ `GrpcConfig.service_name` | `serviceName` |
| `extra` | xhttp | XHttp extra JSON blob | ✅ `XHttpConfig.extra` | `extra` |
| `quicSecurity` | quic | QUIC obfuscation method | ❌ **Missing** | `quicSecurity` |
| `key` | quic | QUIC obfuscation key | ❌ **Missing** | `key` |

#### Protocol-Specific Parameters

| Protocol | URL Param | Description | Our proto_spec |
|----------|-----------|-------------|:---:|
| VLESS | `encryption` | Encryption preset (typically `none`) | ✅ `VlessConfig.encryption` |
| VLESS | `flow` | XTLS flow control (`xtls-rprx-vision`) | ✅ `VlessConfig.flow` |
| VMess | `scy` | Security encryption method | ✅ `VmessConfig.security.enc` |
| VMess | `aid` | Alter ID (must be 0 for AEAD) | ✅ `VmessConfig.alter_id` |
| Trojan | `flow` | Flow control | ✅ (via SecurityConfig) |
| TUIC | `congestion_control` | Congestion control algorithm | ✅ `TuicConfig.congestion_control` |
| Hysteria2 | `obfs` / `obfs-password` | Obfuscation type + password | ✅ `Hysteria2Config` (separate fields) |
| Hysteria2 | `mport` | Port hopping (e.g. `443,8888-9999`) | ❌ **Missing** |
| Hysteria2 | `mportHopInt` | Port hopping interval (seconds) | ❌ **Missing** |
| Hysteria2 | `pinSHA256` | Certificate SHA-256 pin | ❌ **Missing** |
| WireGuard | `publickey` / `public_key` | Peer's public key | ✅ `WireguardConfig.public_key` |
| WireGuard | `presharedkey` / `psk` | Pre-shared key | ✅ `WireguardConfig.preshared_key` |
| WireGuard | `reserved` | Reserved bytes (3-byte) | ✅ `WireguardConfig.reserved` |
| WireGuard | `address` | Interface address CIDR | ✅ `WireguardConfig.address` |
| WireGuard | `mtu` | Interface MTU | ✅ `WireguardConfig.mtu` |
| Shadowsocks | `plugin` | SIP003 plugin (e.g. `obfs-local`) | ❌ **SsConfig precision loss** |
| Shadowsocks | `plugin_opts` | SIP003 plugin options | ❌ **SsConfig precision loss** |

### 24.3 Upstream Fmt File Reference

| Upstream | Dispatch | Parse method | Format method | Shared params |
|----------|----------|-------------|--------------|---------------|
| **v2rayN** (C#) | `FmtHandler.cs` class | `*Fmt.Resolve(string)` | `*Fmt.ToUri(ProfileItem)` | `BaseFmt.ResolveUriQuery` / `BaseFmt.ToUriQuery` |
| **v2rayNG** (Kotlin) | `AngConfigManager.kt:configFmtParsers` map | `*Fmt.parse(String)` | `*Fmt.toUri(ProfileItem)` | `FmtBase.getItemFormQuery` / `FmtBase.getQueryDic` |
| **subconverter** (C++) | `subparser.cpp:explode()` by URL scheme | `explode*(const string&, Proxy&)` | `subexport.cpp:proxyToSingle()` | Protocol-specific in each `explode*` |
| **xray-checker** (Go) | `parser.go:parseShareLink()` | Various per-type | libXray CGO | Protocol-specific |
| **Our** (Rust) | `import_export.rs:parse_share_url()` | `parse_{protocol}()` | `format_{protocol}()` | `common.rs` TransportConfig / TlsOpts |

---

### Thirdparty Repository Snapshots

| Repository | Path | Latest Commit (HEAD) |
|------------|------|---------------------|
| Xray-core | `thirdparty/Xray-core/` | `d7fa207` — Forbid unencrypted outbounds on public Internet for VLESS and Trojan; Remove "none/zero/plain" for VMess and Shadowsocks |
| v2ray-core | `thirdparty/v2ray-core/` | `9db9c4b` — update version to v5.52.0 |
| v2ray-core-legacy | `thirdparty/v2ray-core-legacy/` | `d80440f` — Merge pull request #3085 |
| v2rayN | `thirdparty/v2rayN/` | `ad12a6c` — Update ca cert (#9700) |
| v2rayNG | `thirdparty/v2rayNG/` | `9397a9e` — Fix (#5889) |
| sing-box | `thirdparty/sing-box/` | `0f17638` — Fix v2rayhttp upgrade leak |
| mihomo | `thirdparty/mihomo/` | `2c7309e` — fix: listener duplicate-name check (#2948) |
| quirktiva | `thirdparty/quirktiva/` | `abece1f` — Chore: update test dependencies |
| subconverter | `thirdparty/subconverter/` | `fe6666c` — chore: fix build scripts |
| xray-checker | `thirdparty/xray-checker/` | `f829c2b` — Merge pull request #175 from kutovoys/feat-check-concurrency |
| shoes (Rust proxy impls) | `thirdparty/shoes/` | `607ccde` — reality/reality_tls13_messages.rs: Match Chrome signature algorithms |
| leaf (Rust proxy framework) | `thirdparty/leaf/` | `1d20301` — Revert "feat(inbound): limit data transfer and concurrent connections per IP" |
| shadowsocks-rust | `thirdparty/shadowsocks-rust/` | `f827f6d` — fix(netbsd): use passthrough syntax for RUSTFLAGS in Cross.toml |
| trojan (reference) | `thirdparty/trojan/` | `3e7bb9a` — Update CONTRIBUTORS.md |

> **Refresh**: Update commit hashes after pulling or re-cloning thirdparty repos.
> *Last updated: 2026-07-08*
