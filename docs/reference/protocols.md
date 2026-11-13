# Protocol Configuration Reference

This page answers three questions: what share-URL shape each protocol accepts, which typed config fields that shape fills, and which backend can build or serve the row. Every path, field and capability below is checked against `crates/leas-proto`, `crates/leas-config` and `crates/leas-native`. It does not cover wire formats, TLS engine internals or verification tiers (owned by [`native-core.md`](native-core.md)), Clash YAML key mapping (owned by [`clash.md`](clash.md)), or ordering (owned by [`ordering-law.md`](ordering-law.md)).

## 1. Coverage

### 1.1 Backends

| Backend | What it does | Code |
|---|---|---|
| `xray-core` | Subprocess, JSON config built by `inject_to(CoreType::Xray)` | `crates/leas-proto/src/proto_spec/*.rs`, `crates/leas-core/src/config_builder/xray.rs` |
| `sing-box` | Subprocess, JSON config built by `inject_to(CoreType::SingBox)` | `crates/leas-core/src/config_builder/singbox.rs` |
| Clash / mihomo | YAML import and export of a proxy entry | `crates/leas-proto/src/clash/mod.rs` |
| native | In-process engine, `leas-native` | `crates/leas-native/src/protocol/` |

Core selection is `core_mapping::resolve_core`: `SINGBOX_ONLY_KINDS` forces sing-box, Shadowsocks resolves on its cipher, everything else defaults to xray-core. A per-profile override wins, and the builder then validates against that core.

### 1.2 Matrix

Legend: build = the backend can produce a valid outbound for the config; Clash = YAML import and export both exist; native = the connect-time gate `capability::supported` admits the kind.

| # | Protocol | Kind string | Typed config | xray-core build | sing-box build | Clash | native | Share URL |
|---|---|---|---|---|---|---|---|---|
| 1 | VMess | `vmess` | `VmessConfig` | yes | yes | yes | yes | `vmess://base64(JSON)` |
| 2 | VLESS | `vless` | `VlessConfig` | yes | yes | yes | yes | `vless://uuid@host:port?query` |
| 3 | Trojan | `trojan` | `TrojanConfig` | yes | yes | yes | yes | `trojan://pass@host:port?query` |
| 4 | Shadowsocks | `ss` | `SsConfig` | AEAD only | yes | yes | yes | `ss://base64(method:pass)@host:port?plugin=` |
| 5 | Shadowsocks-2022 | `ss-2022` | `SsConfig` | yes | yes | yes | yes | same `ss://` shape |
| 6 | ShadowsocksR | `ssr` | `SsrConfig` | no | yes | yes | no | `ssr://base64(host:port:proto:method:obfs:base64(pass)/?params)` |
| 7 | SOCKS5 | `socks` | `Socks5Config` | yes | yes | yes | no (see 7) | `socks://user:pass@host:port` |
| 8 | HTTP | `http` | `HttpClientConfig` | yes | yes | yes | no | `http://user:pass@host:port?security=tls` |
| 9 | TUIC | `tuic` | `TuicConfig` | no | yes | yes | no | `tuic://uuid:pass@host:port?query` |
| 10 | Hysteria2 | `hy2` | `Hysteria2Config` | yes | yes | yes | yes | `hysteria2://auth@host:port?query` |
| 11 | Hysteria v1 | `hy` | `Hysteria1Config` | no | yes | yes | no | `hysteria://host:port?query` |
| 12 | WireGuard | `wireguard` | `WireguardConfig` | yes | yes | yes | no | `wireguard://key@host:port?query` |
| 13 | Naïve | `naive` | `NaiveConfig` | no | yes | yes | no | `naive+https://user:pass@host:port` |
| 14 | AnyTLS | `any-tls` | `AnyTlsConfig` | no | yes | yes | yes | `anytls://host:port?password=` |
| 15 | ShadowTLS | `shadow-tls` | `ShadowTlsConfig` | no | yes | yes | no | `shadowtls://host:port?password=` |
| 16 | Tor | `tor` | `TorConfig` | no | yes | yes | no | none, JSON or Clash only |
| 17 | SSH | `ssh` | `SshConfig` | no | yes | yes | no | none, JSON or Clash only |
| 18 | Tailscale | `tailscale` | `TailscaleConfig` | no | yes | yes | no | none, JSON or Clash only |
| 19 | Redirect | `redirect` | `PlaceholderConfig` | no | no | no | no | inbound form, not a destination |
| 20 | TProxy | `t-proxy` | `PlaceholderConfig` | no | no | no | no | inbound form, not a destination |
| 21 | Mixed | `mixed` | `PlaceholderConfig` | no | no | no | no | inbound form, not a destination |

The three placeholder kinds are refused by both builders (`SupportError::UnsupportedProtocol`): sing-box has no redirect/tproxy/mixed outbound type, and a raw legacy body is never a valid outbound. They exist so a feed containing such a row stays importable.

Kind strings and the DB/wire dialect are owned by `ProtocolKind` in `crates/leas-proto/src/proto_spec/kinds.rs`; `FromStr` also accepts the legacy hyphen-less aliases (`hysteria`, `hysteria2`, `anytls`, `shadowtls`, `tproxy`, `hysteria1`).

### 1.3 Endpoint split

Since the host-free parse mandate, no config struct carries host or port. A parse returns `ParsedProto { endpoints, protocol }`: `EndpointEssentials` holds host, host type, primary port and the flattened port list; `ProtocolEssentials::config` holds only endpoint-free parameters. This is why one config pointed at many servers dedups to one `Protocol` row. Reconstruction functions (`reconstruct_proto`) take the endpoint back as an argument.

---

## 2. VMess

- **Scheme**: `vmess://` (base64 of a v2rayN `VmessQRCode` JSON object).
- **Source**: `crates/leas-proto/src/proto_spec/vmess.rs`: `VmessConfig`.
- **Example**: `vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==`

### Fields

| Field | JSON key | Type | Required | Default | Notes |
|---|---|---|---|---|---|
| `uuid` | `id` | `String` | yes | - | Not validated as a UUID |
| host | `add` | `EndpointEssentials.host` | yes | - | Endpoint, not config |
| port | `port` | `EndpointEssentials.port` | yes | - | String or number (`coerce_u16`) |
| `transport` | `net` | `TransportConfig` | no | `Tcp` | Empty, absent or `"null"` means TCP |
| `path` | `path` | `Option<TinyText>` | no | `None` | WS path, gRPC service name mirror, KCP seed |
| transport host | `host` | `WebSocketConfig.host` etc. | no | `None` | Stored only when explicit; never the endpoint host |
| `security.tls` | `tls` | `Option<TlsConfig>` | no | `None` | Any non-empty value means TLS |
| SNI | `sni` | `TlsOpts.sni` | no | `None` | |
| ALPN | `alpn` | `TlsOpts.alpn` | no | `None` | |
| fingerprint | `fp` | `TlsOpts.fp` | no | `None` | |
| `security.enc` | `scy` | `Option<TinyText>` | no | `auto` | Always stored, defaults to `auto` |
| `alter_id` | `aid` | `Option<TinyText>` | no | `None` | Value `"0"`, empty or absent is not stored |
| `insecure` | `insecure` | `TlsOpts.insecure` | no | `None` | `1`/`true`, `0`/`false` |
| `remarks` | `ps` | `Option<TinyText>` | no | `None` | Wrapping quotes stripped |
| - | `type` | `XHttpConfig.mode` | no | `None` | Read only for XHttp |
| - | `v` | not stored | - |: | Version marker, dropped |

### Parser quirks

- Base64 decoding tolerates trailing annotation text and stray backticks (`decode_base64`).
- JSON is parsed permissively (single-quoted keys, trailing commas).
- A missing `id` fails with `MissingConf`; a missing `add` fails with `MissingHost`.
- `net` values `tcp`, `raw`, `auto` and `none` all yield `Tcp`; the last two are generator mistakes that mihomo also accepts.

### Backend coverage

xray-core, sing-box, Clash and native all build. Native transport support is the shared set in §20.

---

## 3. VLESS

- **Scheme**: `vless://<uuid>@<host>:<port>?<query>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/vless.rs`: `VlessConfig`.
- **Example**: `vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws`

### Fields

| Field | Key | Type | Default | Notes |
|---|---|---|---|---|
| `uuid` | userinfo | `String` | - | Required |
| `uuid_origin` | userinfo | `Option<TinyText>` | `None` | Non-UUID userinfo, mapped to a v5 UUID |
| `security` | `security` | `SecurityConfig` | `none` | `none`, `tls`, `reality` |
| `encryption` | `encryption` | `Option<TinyText>` | `None` | Stored unless empty; also the ML-KEM form, see below |
| `flow` | `flow` | `Option<TinyText>` | `None` | `xtls-rprx-vision`, `xtls-rprx-vision-udp443` |
| `transport` | `type` | `TransportConfig` | `tcp` | |
| `path` | `path` | `Option<TinyText>` | `None` | Mirrored from the transport |
| `mux` | `mux`, `muxtype` | `Option<VlessMux>` | `None` | `Limited(n)`, `Unlimited` (`-1`), `Invalid` |
| `splice` | `splice` | `Option<bool>` | `None` | `1`/`0`, `true`/`false` |
| `remarks` | `#` | `Option<TinyText>` | `None` | |

TLS query keys: `sni`, `alpn`, `fp`, and the four verification aliases `allowInsecure`, `allow_insecure`, `allowinsecure`, `skipVerify`. REALITY adds `pbk`, `sid`, `spx`, `pqv` (`RealityOpts.mldsa65_verify`).

The `encryption` value may be an xray `mlkem768x25519plus` string:

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<padding>.<keys>
```

`parse_mlkem_encryption` returns `None` for any other prefix, and errors on an unknown mode, unknown RTT token, bad base64url, or a key segment that is not 32 or 1184 bytes.

### Parser quirks

- Mux presence is the decision, not magnitude: `mux=-1` is `Unlimited`, `mux=0` is inactive, an unparseable value or `muxtype=smux` becomes `Invalid { key, value }` and stays exportable.
- `security` defaults to `none`, unlike Trojan.
- `type` accepts `raw`, `auto` and `none` as TCP. For `type=grpc`, the service name arrives through `path`; no `serviceName` query key is read, though the module header claims one.
- An XHttp `mode` outside `auto`, `packet-up`, `stream-up`, `stream-one` is first passed through `recover_xhttp_mode`; if that fails the parse errors. A non-JSON `extra` errors.

### Backend coverage

xray-core, sing-box, Clash, native.

---

## 4. Trojan

- **Scheme**: `trojan://<password>@<host>:<port>?<query>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/trojan.rs`: `TrojanConfig`.
- **Example**: `trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org`

### Fields

| Field | Key | Type | Default | Notes |
|---|---|---|---|---|
| `password` | userinfo | `String` | - | Required; `#` in a password is handled by the splitter |
| `security` | `security` | `SecurityConfig` | `tls` | `tls`, `none`, `reality` |
| `transport` | `type` | `TransportConfig` | `tcp` | |
| `path` | `path` | `Option<TinyText>` | `None` | Mirrored from the transport |
| `remarks` | `#` | `Option<TinyText>` | `None` | |

TLS keys match VLESS. REALITY accepts `pbk`, `sid`, `spx`, `pqv`.

### Parser quirks

- `security` absent means `tls`; `security=none` must be explicit.
- The parser reads `sni` only. Export defaults fill an absent SNI with the resolved host (`set_export_defaults`); the config stores only explicit values. The module header mentions a `peer` fallback, but no code reads a `peer` key.
- Only `type` and `path` are read; the module header's `ws=1` + `wspath=` legacy form is not implemented.

### Backend coverage

xray-core, sing-box, Clash, native.

---

## 5. Shadowsocks and Shadowsocks-2022

- **Scheme**: `ss://`. Three accepted shapes:
  - SIP002: `ss://base64url_no_pad(method:password)@host:port?plugin=...#remarks`
  - Legacy QR: `ss://base64(method:password@host:port)`
  - Plain: `ss://method:password@host:port`
- **Source**: `crates/leas-proto/src/proto_spec/ss.rs`: `SsConfig`, plugin in `proto_spec/ss_plugin.rs`.
- **Example**: `ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388` (`aes-256-gcm:pass`).

### Fields

| Field | Source | Type | Required | Notes |
|---|---|---|---|---|
| `method` | userinfo | `TinyText` | yes | Cipher; decides the kind |
| `password` | userinfo | `String` | yes | |
| host, port | hostport | `EndpointEssentials` | yes | No implicit port: `parse_hostport` requires one |
| `plugin` | `plugin` query | `Option<PluginSpec>` | no | Typed, lossless |
| `security` | - | `SecurityConfig` | empty | Only `none` (no URL key) |
| `remarks` | `#` | `Option<TinyText>` | no | |

### Ciphers

The native roster (`leas-native/src/protocol/ss/method.rs`, case-insensitive, aliases included):

| Family | Methods |
|---|---|
| AEAD-2017 | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305` (= `chacha20-ietf-poly1305`), `xchacha20-poly1305` (= `xchacha20-ietf-poly1305`), plus `aead_*` aliases |
| 2022-blake3 | `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| Legacy stream | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `rc4-md5`, `chacha20-ietf`, `xchacha20`, `none` |

The three families dispatch to three codecs: `stream.rs` (AEAD-2017), `stream2022.rs` (BLAKE3), `stream_legacy.rs` (IV-prefixed stream cipher, no chunk framing).

Builder gates (`proto_spec/core_mapping.rs`):

- `XRAY_SS_METHODS`: AEAD-2017 plus 2022-blake3, with the `aead_*`, `chacha20-poly1305` and `xchacha20-poly1305` aliases. A legacy cipher against xray-core is a build error.
- `SINGBOX_SS_METHODS`: the whole list above, including `aes-192-gcm` and `none`.
- `resolve_core` sends a method xray accepts to xray-core and anything else to sing-box, then the builder validates.

### Kind and core

`proto_kind_for_method` returns `Shadowsocks2022` (`ss-2022`) for `2022-blake3-*` and `Shadowsocks` (`ss`) otherwise. Both share `SsConfig`. This is the only kind whose core depends on a field.

### Plugin

`PluginSpec` is total by construction: `name` (verbatim, may be empty), `family` (`Obfs`, `V2Ray`, `Unknown`), `mode` (`Unset`, `Http`, `Tls`, `Websocket`, `Quic`, `Invalid`), `host`, `port`, `path`, `tls` (`Unset`/`On`), `mux` (`Unset`, `Off`, `On(n)`, `Invalid`), and a sorted `extra` map for keys it preserves but does not interpret (`obfs-uri`, unknown keys).

- `obfs=tls` is the obfs transport's synthetic hello, not encryption.
- There is no `obfs=plain`; that spelling belongs to ShadowsocksR.
- sing-box receives `plugin` (name) plus `render_opts()` (sorted canonical option string).
- xray-core has no SIP003 support at all, so a plugin row against xray-core is a build error rather than a config that dials the bare server.

### Import admission rules

`validate_ss_config` in `crates/leas-config/src/import_export.rs` runs inside `parse_share_url` and in the form path. A row that fails is dropped, never stored:

1. Malformed 2022 PSK: `ss2022_password_usable` requires base64 or the exact raw key length. A `:`-separated multi-user key is valid and passes.
2. `none` on a cleartext wire: refused unless the row carries a real TLS layer (`security` tls/reality, or plugin `tls=1`). `obfs=tls` does not count.
3. `mode=quic`: refused. The peer speaks QUIC draft-29/32/34 (v2ray-plugin 1.3.2 embeds v2ray-core 4.38.3 / quic-go 0.20.1) and every QUIC stack here speaks RFC 9000 v1.

### Parser quirks

- A userinfo that does not decode to `method:password` is treated as the plain form.
- Missing `:` in the decoded userinfo is `InvalidUserInfo`.
- IPv6 hosts must be bracketed; reconstruction re-brackets them.

### Backend coverage

xray-core builds only AEAD and 2022 ciphers and refuses any plugin. sing-box builds every method and the plugin fields. Clash imports and exports. Native serves all three cipher families over TCP; the UDP leg refuses a non-empty `security` and is not reachable through the proxy outbound (see `capability.rs`).

---

## 6. ShadowsocksR

- **Scheme**: `ssr://<base64url(host:port:protocol:method:obfs:base64(password)/?params)>`.
- **Source**: `crates/leas-proto/src/proto_spec/ssr.rs`: `SsrConfig`.
- **Example**: `ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjpyYzQtbWQ1OnBsYWluOmNHRnpjM2R2Y21RLz9ncm91cD1WR1Z6ZEVkeWIzVncmcmVtYXJrcz1WR1Z6ZEZObGNuWmxjZw`

### Fields

| Field | Position | Type | Required |
|---|---|---|---|
| `protocol` | 4th from end | `TinyText` | yes |
| `method` | 3rd from end | `TinyText` | yes |
| `obfs` | 2nd from end | `TinyText` | yes |
| `password` | last (base64) | `String` | yes |
| host | everything before the last 5 fields | endpoint | yes |
| port | 5th from end | endpoint | yes |

The struct also stores `params: HashMap<String, String>`, seeded with `protocol` and `obfs` and then every `&`-separated query pair.

### Parser quirks

- Splitting counts from the end, so an IPv6 host with colons works.
- The last field may carry `/?` or `?` before the query; password is everything before it.
- `remarks` is removed from `params` and decoded into `self.remarks`; `group`, `obfsparam`, `protoparam` stay in the map.
- `clean_ssr_userinfo` strips trailing non-base64 annotation before decoding.
- Fewer than six colon-separated fields is `InvalidStructure`.

### Backend coverage

sing-box only; Clash imports and exports; native has a placeholder module and the gate refuses the kind.

---

## 7. SOCKS5

- **Scheme**: `socks://[user:pass@]host:port#remarks`.
- **Source**: `crates/leas-proto/src/proto_spec/socks.rs`: `Socks5Config`.
- **Example**: `socks://user:pass@1.2.3.4:1080`

### Fields

| Field | Source | Type | Required |
|---|---|---|---|
| `username` | userinfo | `Option<String>` | no |
| `password` | userinfo | `Option<String>` | no |
| `security` | - | `SecurityConfig` | empty (no URL key) |
| `remarks` | `#` | `Option<TinyText>` | no |
| host, port | hostport | endpoint | yes |

### Parser quirks

- A userinfo without `:` is a username with no password.
- `userinfo == hostport` means the URL had no `@`; both fields stay `None`.
- A URL with no `@` and no `hostport` splits the collapsed userinfo at the first `@`.
- No default port; `1080` is the upstream convention, not applied here.

### Backend coverage

xray-core and sing-box build. Clash imports and exports. Native has a working SOCKS5 client codec (`protocol/socks/mod.rs`) but `NATIVE_KINDS` does not include `Socks`, so the connect gate refuses the row.

---

## 8. HTTP

- **Scheme**: `http://[user:pass@]host[:port][?security=tls&sni=...]`.
- **Source**: `crates/leas-proto/src/proto_spec/http_client.rs`: `HttpClientConfig`.
- **Example**: `http://user:pass@1.2.3.4:8080`

### Fields

| Field | Source | Type | Required | Notes |
|---|---|---|---|---|
| `username`, `password` | userinfo | `Option<String>` | no | Basic auth |
| `security` | `security=tls` | `SecurityConfig` | empty | Plain HTTP unless `security=tls` |
| `remarks` | `#` | `Option<TinyText>` | no | |
| host | hostport | endpoint | yes | |
| port | hostport | endpoint | no in-shape | Defaults to 80 when the hostport has no colon |

TLS keys when `security=tls`: `sni`, `alpn`, `fp`, and the four verification aliases.

### Parser quirks

- A URL with no `@` has `userinfo == hostport` and yields no credentials.
- Only `security=tls` enables TLS; any other value means plain.

### Backend coverage

xray-core and sing-box build. Clash imports and exports. Native has a placeholder module (`protocol/http/mod.rs`), and the gate refuses the kind.

---

## 9. TUIC

- **Scheme**: `tuic://<uuid>:<password>@<host>:<port>?<query>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/tuic.rs`: `TuicConfig`.
- **Example**: `tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3`

### Fields

| Field | Key | Type | Notes |
|---|---|---|---|
| `uuid` | userinfo | `String` | Parsed and validated as a UUID |
| `password` | userinfo | `String` | Everything after the first `:` |
| `congestion_control` | `congestion_control` | `Option<TinyText>` | No default applied at parse |
| `udp_relay_mode` | `udp_relay_mode` | `Option<TinyText>` | |
| `security` | `sni`, `alpn`, verification aliases | `SecurityConfig` | TLS is always present |

### Parser quirks

- An invalid UUID is `InvalidUserInfo`.
- The userinfo must be `uuid:password`.

### Backend coverage

sing-box only (`SINGBOX_ONLY_KINDS`, and the xray arm returns `UnsupportedProtocol`). Clash imports and exports. Native has a placeholder module and the gate refuses the kind. QUIC dialing in the native engine exists only for Hysteria2.

---

## 10. Hysteria2

- **Scheme**: `hysteria2://` and `hy2://`.
- **Source**: `crates/leas-proto/src/proto_spec/hysteria2.rs`: `Hysteria2Config`.
- **Example**: `hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com`

### Fields

| Field | Key | Type | Notes |
|---|---|---|---|
| `auth` | userinfo | `String` | Single token or `user:pass`, kept verbatim |
| port | hostport | `EndpointEssentials` | `PortSpec`: single, list, range, mixed, capped at `MAX_PORTS` = 4096 |
| `obfs` | `obfs` | `Option<TinyText>` | e.g. `salamander` |
| `obfs_password` | `obfs-password` | `Option<TinyText>` | |
| `up` | `up` | `Option<TinyText>` | Raw string |
| `down` | `down` | `Option<TinyText>` | Raw string |
| `hop_interval` | `mportHopInt`, `hop_interval` | `Option<u32>` | Seconds |
| `pin_sha256` | `pinSHA256`, `pin_sha256` | `Option<TinyText>` | Certificate pin |
| `security` | `sni`, `insecure` | `SecurityConfig` | TLS always present |
| `remarks` | `#` | `Option<TinyText>` | |

### Parser quirks

- `insecure` accepts `1`/`true`/`yes` and `0`/`false`/`no`.
- `obfs-password` uses a hyphen, not an underscore.
- A multi-port hostport fills `endpoint.ports` with the flattened list.
- A URL with no `@` splits the collapsed userinfo at the first `@`.

### Backend coverage

Both subprocesses build. Clash imports and exports. Native serves it as a QUIC dial (`protocol/hysteria2/quic.rs`); it is not a stream protocol, so a stream chain refuses it. Salamander obfuscation is implemented in `leas-native/src/crypto/salamander.rs`.

---

## 11. Hysteria v1

- **Scheme**: `hysteria://` and `hy://`.
- **Source**: `crates/leas-proto/src/proto_spec/hysteria1.rs`: `Hysteria1Config`.
- **Example**: `hysteria://example.com:443?protocol=udp&obfs=xplus&up_mbps=200&down_mbps=200&insecure=1&sni=real.example.com`

### Fields

| Field | Key | Type | Default | Notes |
|---|---|---|---|---|
| `auth` | userinfo | `Option<String>` | `None` | Absent when `userinfo == hostport` |
| `protocol` | `protocol`, `type` | `Option<TinyText>` | `None` | `udp`, `wechat-video`, `faketcp` |
| `obfs` | `obfs` | `Option<TinyText>` | `None` | `xplus`, `salamander` |
| `up_mbps` | `up_mbps`, `upmbps` | `Option<u32>` | `None` | Value `100` is not stored |
| `down_mbps` | `down_mbps`, `downmbps` | `Option<u32>` | `None` | Value `100` is not stored |
| `security` | `sni`, verification aliases | `SecurityConfig` | TLS always present | |
| port | hostport | endpoint | 443 | Bare host accepted |

### Parser quirks

- No port means 443; a bare host is valid.
- `insecure` accepts `1`/`true`/`yes` and `0`/`false`/`no`.
- The 100 Mbps defaults are the upstream defaults and are elided from storage.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder and the gate refuses the kind.

---

## 12. WireGuard

- **Scheme**: `wireguard://<percent-encoded private key>@<host>:<port>?<query>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/wireguard.rs`: `WireguardConfig`.
- **Example**: `wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280`

### Fields

| Field | Key | Type | Required |
|---|---|---|---|
| `private_key` | userinfo (percent-decoded) | `String` | yes |
| `address` | `address` | `TinyText` | yes |
| `public_key` | `publickey`, `public_key` | `String` | yes |
| `preshared_key` | `presharedkey`, `psk` | `Option<String>` | no |
| `reserved` | `reserved` | `Option<TinyText>` | no |
| `mtu` | `mtu` | `Option<TinyText>` | no |
| `persistent_keepalive` | `persistent_keepalive`, `keepalive` | `Option<u32>` | no |
| `dns` | `dns` | `Option<Vec<String>>` | no |
| `remote_dns_resolve` | `remote_dns_resolve`, `remote_dns` | `Option<bool>` | no |

### Parser quirks

- The private key is percent-decoded, so `+`, `/` and `=` must be escaped.
- `reserved` accepts comma-separated decimals or base64 bytes and is stored verbatim.
- No default port; `2408` is the v2rayN convention and `51820` the WireGuard one, neither applied by this parser.
- `mtu` is stored as text, not parsed to `u16`.

### Backend coverage

xray-core and sing-box build. Clash imports and exports. Native has a placeholder module; the gate refuses the kind.

---

## 13. Naïve

- **Scheme**: `naive+https://<user>:<password>@<host>:<port>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/naive.rs`: `NaiveConfig`.
- **Example**: `naive+https://user:pass@example.com:443`

### Fields

| Field | Source | Type | Required |
|---|---|---|---|
| `username` | userinfo | `String` | yes |
| `password` | userinfo | `String` | yes |
| `security` | - | `SecurityConfig` | TLS always present |
| `remarks` | `#` | `Option<TinyText>` | no |

### Parser quirks

- The userinfo must contain `:`; otherwise `InvalidUserInfo`.
- `naive+https://` and `naive+quic://` both route to this parser, and the config records neither, so reconstruction always writes `naive+https://`.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder.

---

## 14. AnyTLS

- **Scheme**: `anytls://<host>:<port>?password=<pw>&sni=<sni>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/anytls.rs`: `AnyTlsConfig`.
- **Example**: `anytls://1.2.3.4:8080?password=secret`

### Fields

| Field | Key | Type | Required |
|---|---|---|---|
| `password` | `password`, `auth` | `Option<String>` | no |
| `security` | `sni`, `alpn`, `insecure`/`allow_insecure`/`allowinsecure`/`skipVerify` | `SecurityConfig` | empty unless a TLS key is present |
| `remarks` | `#` | `Option<TinyText>` | no |

### Parser quirks

- TLS is implied by the protocol, but `SecurityConfig` stays empty when the URL carries no TLS key; the builder supplies TLS.
- No `fp` key is read.

### Native client

`crates/leas-native/src/protocol/anytls/` implements the full client side
(`thirdparty/anytls-go/docs/protocol.md`):

| Piece | Behaviour |
|---|---|
| Auth | `sha256(password) | u16 padding0 len | padding0`, sent before anything else |
| Session | `cmd:u8 | id:u32 BE | len:u16 BE | data`; commands 0–10 |
| Padding | the stock `stop=8` scheme; a server `cmdUpdatePaddingScheme` replaces it for later sessions of the same link |
| Reuse | one session carries many streams; the newest idle session is taken first, idle ones are closed after 60 s (30 s scan, newest 2 kept) |
| TCP | `cmdSYN` + `cmdPSH(SOCKS5 address)` opens a stream, `cmdFIN` closes it |
| UDP | sing-box uot v2 on a stream to `sp.v2.udp-over-tcp.arpa`, per-packet addresses (`isConnect=false`) |
| v2 control | `cmdServerSettings` marks the auth ack ok, `cmdAlert` marks it failed, `cmdHeartRequest` is answered; the reference's missing-`cmdSYNACK` session watchdog is deliberately not implemented |

Only the first link of a chain pools sessions; a chained AnyTLS hop opens one
stream on the session carried by its upstream tunnel. The e2e oracles are
sing-box and mihomo (`crates/leas-oracles/tests/anytls.rs`).

### Backend coverage

sing-box only. Clash imports and exports (mihomo and quirktiva carry the same option shape). Native has a placeholder.

---

## 15. ShadowTLS

- **Scheme**: `shadowtls://<host>:<port>?password=<pw>&version=<n>&sni=<sni>#<remarks>`.
- **Source**: `crates/leas-proto/src/proto_spec/shadowtls.rs`: `ShadowTlsConfig`.
- **Example**: `shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com`

### Fields

| Field | Key | Type | Required |
|---|---|---|---|
| `password` | `password` | `Option<String>` | no |
| `version` | `version` | `Option<TinyText>` | no |
| `security` | `sni` | `SecurityConfig` | empty unless `sni` is present |
| `remarks` | `#` | `Option<TinyText>` | no |

### Parser quirks

- Only `sni` reaches the security block; `alpn`, `fp` and the verification keys are not read.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder.

---

## 16. Tor

- **Scheme**: none. There is no share URL.
- **Source**: `crates/leas-proto/src/proto_spec/tor.rs`: `TorConfig`.
- **Example**: Clash entry or JSON only.

### Fields

| Field | Type | Notes |
|---|---|---|
| `executable_path` | `Option<String>` | Tor binary path |
| `extra_args` | `Option<Vec<String>>` | Extra CLI arguments |
| `data_directory` | `Option<String>` | |
| `torrc` | `Option<HashMap<String, String>>` | Additional torrc options |
| `security` | `SecurityConfig` | |
| `remarks` | `Option<TinyText>` | |

### Parser quirks

`try_parse_proto` and `reconstruct_proto` both return an error naming the missing URL format. Import comes from Clash (`ClashTor`) or the form.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder.

---

## 17. SSH

- **Scheme**: none. There is no share URL.
- **Source**: `crates/leas-proto/src/proto_spec/ssh.rs`: `SshConfig`.

### Fields

| Field | Type | Notes |
|---|---|---|
| `user` | `Option<String>` | |
| `password` | `Option<String>` | |
| `private_key` | `Option<String>` | Single key body |
| `private_key_path` | `Option<String>` | |
| `private_key_passphrase` | `Option<String>` | |
| `host_key` | `Option<Vec<String>>` | Accepted host keys |
| `host_key_algorithms` | `Option<Vec<String>>` | |
| `client_version` | `Option<String>` | |
| `security` | `SecurityConfig` | |
| `remarks` | `Option<TinyText>` | |

### Parser quirks

Both URL functions return an error naming the missing URL format. Import from Clash (`ClashSsh`) or the form.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder.

---

## 18. Tailscale

- **Scheme**: none. There is no share URL.
- **Source**: `crates/leas-proto/src/proto_spec/tailscale.rs`: `TailscaleConfig`.

### Fields

| Field | Type | Notes |
|---|---|---|
| `hostname` | `Option<String>` | |
| `auth_key` | `Option<String>` | |
| `control_url` | `Option<String>` | |
| `state_directory` | `Option<String>` | |
| `ephemeral` | `Option<bool>` | |
| `accept_routes` | `Option<bool>` | |
| `exit_node` | `Option<String>` | |
| `exit_node_allow_lan_access` | `Option<bool>` | |
| `advertise_routes` | `Option<Vec<String>>` | Stored as text, not parsed prefixes |
| `security` | `SecurityConfig` | |
| `remarks` | `Option<TinyText>` | |

### Parser quirks

Both URL functions return an error naming the missing URL format. Import from Clash (`ClashTailscale`) or the form.

Upstream sing-box also models `advertise_exit_node`, `advertise_tags`, `relay_server_port`, `system_interface` and `udp_timeout`; none of those exist on this struct, so a Clash or JSON row carrying them loses them.

### Backend coverage

sing-box only. Clash imports and exports. Native has a placeholder.

---

## 19. Inbound forms: Redirect, TProxy, Mixed

- **Scheme**: none.
- **Source**: `PlaceholderConfig` in `crates/leas-proto/src/proto_spec/mod.rs`.

These three kinds share one type: an opaque legacy body (`proto_name` plus `settings_json`, holding `protocol_settings` and `stream_settings`) with no endpoint.

| Kind | ProtocolKind | Outbound build | Notes |
|---|---|---|---|
| Redirect | `Redirect` | refused on both cores | Listen-side form |
| TProxy | `TProxy` | refused on both cores | Listen-side form |
| Mixed | `Mixed` | refused on both cores | SOCKS and HTTP on one port |

### Parser quirks

- `try_parse_proto` derives the kind from `proto_name`; an unknown name falls back to `Mixed`.
- `reconstruct_proto` and both Clash functions always error.
- Identity hashes `proto_name` plus the whole body, including `remarks`, so renaming a profile changes its uid. That is the mandated whole-body hash for opaque configs, not a bug.

### Backend coverage

Neither subprocess builds an outbound: sing-box has no such outbound type, and a raw body without a `type` key is not a valid outbound. The native engine has placeholder modules for the three kinds; inbound side, see `leas-native/src/inbound/`.

---

## 20. Transport configuration

**Source**: `crates/leas-proto/src/proto_spec/common.rs`: `TransportConfig`.

| Variant | Wire string | VMess `net=` | VLESS/Trojan `type=` |
|---|---|---|---|
| `Tcp` | `tcp` | `tcp` | `tcp` |
| `Ws(WebSocketConfig)` | `ws` | `ws`, `websocket` | `ws`, `websocket` |
| `Grpc(GrpcConfig)` | `grpc` | `grpc` | `grpc` |
| `Http(HttpConfig)` | `http` | `http`, `h2`, `https` | `http`, `h2`, `https` |
| `Quic` | `quic` | `quic` | `quic` |
| `Kcp(KcpConfig)` | `kcp` | `kcp`, `mkcp` | `kcp`, `mkcp` |
| `HttpUpgrade(HttpUpgradeConfig)` | `httpupgrade` | `httpupgrade` | `httpupgrade` |
| `XHttp(XHttpConfig)` | `xhttp` | `splithttp`, `xhttp` | `splithttp`, `xhttp` |

Only VLESS, VMess and Trojan carry a transport. Every other config returns `None` from `transport_mut()`, including Shadowsocks, whose plugin row is dispatched first in the native upgrade step.

### WebSocketConfig

| Field | Type | Notes |
|---|---|---|
| `path` | `Option<TinyText>` | Canonicalized at build |
| `host` | `Option<TinyText>` | Host header |
| `headers` | `Option<HashMap<String, String>>` | |
| `max_early_data` | `Option<u32>` | |
| `early_data_header_name` | `Option<TinyText>` | |
| `v2ray_http_upgrade` | `Option<bool>` | |
| `v2ray_http_upgrade_fast_open` | `Option<bool>` | |

### GrpcConfig

| Field | Type | Notes |
|---|---|---|
| `path` | `Option<TinyText>` | Legacy service-name mirror |
| `authority` | `Option<TinyText>` | `:authority` override |
| `service_name` | `Option<TinyText>` | Preferred service name |
| `mode` | `Option<TinyText>` | gRPC mode |
| `user_agent` | `Option<TinyText>` | |
| `ping_interval` | `Option<u32>` | |

### HttpConfig

| Field | Type |
|---|---|
| `path` | `Option<TinyText>` |
| `host` | `Option<TinyText>` |
| `method` | `Option<TinyText>` |
| `headers` | `Option<HashMap<String, String>>` |
| `idle_timeout` | `Option<u32>` |
| `ping_timeout` | `Option<u32>` |

### KcpConfig

`mtu`, `tti`, `uplink_capacity`, `downlink_capacity`, `congestion` (`Option<bool>`), `read_buffer`, `write_buffer` are `Option<u32>`/`Option<bool>`; `seed` and `header_type` are `Option<TinyText>`.

### HttpUpgradeConfig

`path`, `host`, `headers`, and `ed` (`Option<u32>`, early-data size).

### XHttpConfig

`path`, `host`, `mode` (`auto`, `packet-up`, `stream-up`, `stream-one`), `headers`, and `extra` (raw `serde_json::Value`).

### Quic

`TransportConfig::Quic` is a unit variant; no option field is modelled. `QuicOpts` (`security`, `key`) exists in `common.rs` but has no user, so `quicSecurity` and `key` from a share URL are dropped.

### Native transport support

`leas-native/src/transport/mod.rs` dials `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `xhttp` (plus HTTP/3 when xhttp carries a single `h3` ALPN) and `kcp`. The `quic` transport returns `NotImplemented`; QUIC exists only as a protocol dial for Hysteria2.

---

## 21. TLS and security configuration

**Source**: `crates/leas-proto/src/proto_spec/common.rs`: `SecurityConfig`, `TlsConfig`, `TlsOpts`, `RealityOpts`. The engine lives in `crates/leas-tls`, documented in [`native-core.md`](native-core.md).

### SecurityConfig

| Field | Type | Notes |
|---|---|---|
| `tls` | `Option<TlsConfig>` | Flattened into the same JSON object |
| `enc` | `Option<TinyText>` | VMess `scy` |

`TlsConfig` is `Tls(TlsOpts)` or `Reality(RealityOpts)`.

### TlsOpts

| Field | Type | Share-URL key |
|---|---|---|
| `sni` | `Option<TinyText>` | `sni` |
| `alpn` | `Option<TinyText>` | `alpn` |
| `curves` | `Option<TinyText>` | none; JSON `curvePreferences` only |
| `fp` | `Option<TinyText>` | `fp` |
| `insecure` | `Option<bool>` | four aliases |
| `ech` | `Option<TinyText>` | none; JSON only |
| `vcn` | `Option<bool>` | none; JSON only |
| `pcs` | `Option<TinyText>` | none; JSON only |
| `pin_sha256` | `Option<TinyText>` | `pinSHA256` on Hysteria2 only |

### RealityOpts

| Field | Type | Share-URL key |
|---|---|---|
| `sni` | `Option<TinyText>` | `sni` |
| `fp` | `Option<TinyText>` | `fp` |
| `pbk` | `Option<String>` | `pbk` |
| `sid` | `Option<TinyText>` | `sid` |
| `spx` | `Option<TinyText>` | `spx` |
| `mldsa65_verify` | `Option<String>` | `pqv` (serde alias `pqv`) |

REALITY exists on VLESS and Trojan only; neither VMess nor any other config reads `pbk`.

### Precision note

The share-URL surface covers the fields a feed actually carries. The remaining sing-box `OutboundTLSOptions` fields (`min_version`, `max_version`, `cipher_suites`, `certificate`, ECH chain, uTLS config) are JSON-config only, so there is no URL round-trip loss. They are also not modelled as typed fields, so a JSON config that carries them does not round-trip through this type.

---

## 22. Internal kinds

These are `ProtocolKind` variants with no share URL and no outbound build. The enum and its string dialect live in `crates/leas-proto/src/proto_spec/kinds.rs`.

| Kind | String | Treatment |
|---|---|---|
| `Freedom` | `freedom` | Direct outbound; routing only |
| `Blackhole` | `blackhole` | Block outbound; routing only |
| `Dns` | `dns` | DNS outbound; routing only |
| `Loopback` | `loopback` | Loopback to another inbound; routing only |
| `Custom` | `custom` | Plugin outbound; routing only |
| `DokodemoDoor` | `dokodemo` | Door inbound; routing only |

`Shadowsocks2022` is not in this list: it is a full protocol kind with its own string (`ss-2022`) and shares `SsConfig` with `ss`.

The legacy `config_type` integers (`1`–`27`) still map through `ProtocolKind::try_from_i32` / `to_i32`, because `ProfileKey` and fast-ping dispatch are i32-based.

---

## 23. Precision notes and known gaps

### Confirmed precision loss

| # | Protocol | Field | Impact | Priority |
|---|---|---|---|---|
| 1 | ShadowsocksR | `obfsparam`, `protoparam` | Kept in the generic `params` map, no typed access; round-trip preserved | low |
| 2 | Hysteria2 | `up`, `down` | Stored as text; the builder parses Mbps | low |
| 3 | Quic transport | `quicSecurity`, `key` | Dropped: `Quic` has no options and `QuicOpts` is unused | medium |
| 4 | Tailscale | five upstream-only fields | Not modelled; lost on import | medium |
| 5 | All TLS | `min_version`, `max_version`, `cipher_suites`, `certificate`, ECH chain | Not modelled; JSON-only in upstream, and lost on JSON round-trip here | medium |
| 6 | Redirect, TProxy, Mixed | entire config | Opaque legacy body, no typed fields | medium |

### Fields kept in the URL but not in a typed field

`vmess://` `v` (always `"2"`) and `type` (XHttp mode only) are read for parsing and dropped from the struct.

### Round-trip test coverage

| Test | Scope | Location |
|---|---|---|
| `corpus_plugin_rows_parse_and_round_trip` | Parses every fixture containing a SIP003 plugin row, exports, re-imports, compares | `proto_spec/ss.rs` |
| Per-config parse and reconstruct tests | One or more example URLs per typed config | `#[cfg(test)]` in each `proto_spec/*.rs` |
| Dispatch and inject coverage | One URL per kind through `inject_to` on its supporting core | `proto_spec/mod.rs` tests |
| All-fields round-trip | none | no test exercises every optional field |
| JSON config round-trip | none | no `to_json_config` then parse test |
| Page filter and ordering tests | not protocol scope | see [`ordering-law.md`](ordering-law.md) |

There is no shared `check_roundtrip` helper; the earlier "all 8 real configs" claim described a helper that no longer exists, and the typed set is now 17.

### Upstream references

| Protocol group | Upstream |
|---|---|
| VMess | Xray-core `proxy/vmess/account.proto`; v2rayN `ServiceLib/Models/Dto/VmessQRCode.cs`; sing-box `option/vmess.go`; mihomo `adapter/outbound/vmess.go` |
| VLESS | Xray-core `proxy/vless/account.proto`; sing-box `option/vless.go`; v2rayN `VLESSFmt.cs`; mihomo `adapter/outbound/vless.go` |
| Trojan | trojan-gfw `src/core/config.h`; Xray-core `proxy/trojan/protocol.go`; sing-box `option/trojan.go`; mihomo `adapter/outbound/trojan.go` |
| Shadowsocks | shadowsocks-rust `src/config.rs`; SIP002 spec; sing-box `option/shadowsocks.go`; mihomo `adapter/outbound/shadowsocks.go` |
| ShadowsocksR | sing-box `option/shadowsocksr.go`; subconverter `explodeSSR()`; mihomo `adapter/outbound/shadowsocksr.go` |
| SOCKS5 | sing-box `option/simple.go`; mihomo `adapter/outbound/socks5.go`; Xray-core `proxy/socks/config.proto` |
| HTTP | sing-box `option/simple.go`; mihomo `adapter/outbound/http.go`; Xray-core `proxy/http/config.proto` |
| TUIC | sing-box `option/tuic.go`; mihomo `adapter/outbound/tuic.go` |
| Hysteria2 | Hysteria2 `app/internal/url/url.go`; sing-box `option/hysteria2.go`; mihomo `adapter/outbound/hysteria2.go` |
| Hysteria v1 | sing-box `option/hysteria.go` |
| WireGuard | sing-box `option/wireguard.go`; Xray-core `proxy/wireguard/config.proto`; mihomo `adapter/outbound/wireguard.go` |
| Naïve | sing-box `option/naive.go` |
| AnyTLS | sing-box `option/anytls.go`; mihomo and quirktiva `adapter/outbound/anytls.go` |
| ShadowTLS | sing-box `option/shadowtls.go` |
| Transports | Xray-core `transport/internet/*/config.proto`; sing-box `option/v2ray_transport.go` |

---

## 24. Share-URL parameter vocabulary

The names below are the de-facto standard shared by v2rayN and v2rayNG. Per-protocol support in this repository is the matrix in §1.2 plus the parser notes in each section.

### 24.1 TLS and security

| Parameter | Meaning | This code |
|---|---|---|
| `security` | TLS mode: `tls`, `reality`, `none` | `SecurityConfig` |
| `sni` | SNI override | `TlsOpts.sni`, `RealityOpts.sni` |
| `alpn` | ALPN list | `TlsOpts.alpn` |
| `fp` | uTLS Client Hello fingerprint | `TlsOpts.fp`, `RealityOpts.fp` |
| `pbk` | REALITY public key | `RealityOpts.pbk` |
| `sid` | REALITY short ID | `RealityOpts.sid` |
| `spx` | REALITY spider X | `RealityOpts.spx` |
| `pqv` | REALITY ML-DSA-65 verification key | `RealityOpts.mldsa65_verify` |
| `insecure`, `allowInsecure`, `allow_insecure`, `skipVerify` | Skip certificate verification | `TlsOpts.insecure` |
| `ech` | Encrypted Client Hello list | not read; `TlsOpts.ech` is JSON-only |
| `vcn` | Verify peer certificate by name | not read; `TlsOpts.vcn` is JSON-only |
| `pcs` | Certificate SHA-256 pin | not read; `TlsOpts.pin_sha256` is JSON-only except Hysteria2 `pinSHA256` |
| `fm` | Finalmask JSON blob | not supported |

### 24.2 Transport

| Parameter | Transport | Meaning | This code |
|---|---|---|---|
| `type` | all | Transport type | `TransportConfig` |
| `host` | tcp, ws, http, xhttp, httpupgrade | Transport host header | per-type `host` |
| `path` | tcp, ws, http, xhttp, httpupgrade | Transport path | per-type `path` |
| `headerType` | tcp, kcp | Header obfuscation | `KcpConfig.header_type` only |
| `seed` | kcp | KCP seed | `KcpConfig.seed` |
| `mtu`, `tti` | kcp | KCP tuning | `KcpConfig.mtu`, `.tti` |
| `mode` | grpc, xhttp | gRPC mode, XHttp mode | `GrpcConfig.mode`, `XHttpConfig.mode` |
| `authority` | grpc | `:authority` override | `GrpcConfig.authority` |
| `serviceName` | grpc | Service name | `GrpcConfig.service_name` |
| `extra` | xhttp | Extra JSON blob | `XHttpConfig.extra` |
| `quicSecurity`, `key` | quic | QUIC obfuscation | dropped (§20) |

### 24.3 Protocol-specific

| Protocol | Parameter | Meaning | This code |
|---|---|---|---|
| VLESS | `encryption` | Encryption preset, or the `mlkem768x25519plus` string | `VlessConfig.encryption` |
| VLESS | `flow` | XTLS flow | `VlessConfig.flow` |
| VLESS | `mux`, `muxtype` | Mux request | `VlessConfig.mux` |
| VMess | `scy` | Encryption method (default `auto`) | `SecurityConfig.enc` |
| VMess | `aid` | Alter ID | `VmessConfig.alter_id` |
| TUIC | `congestion_control` | Congestion control | `TuicConfig.congestion_control` |
| TUIC | `udp_relay_mode` | UDP relay mode | `TuicConfig.udp_relay_mode` |
| Hysteria2 | `obfs`, `obfs-password` | Obfuscation type and key | `Hysteria2Config.obfs`, `.obfs_password` |
| Hysteria2 | `mportHopInt`, `hop_interval` | Port-hopping interval, seconds | `Hysteria2Config.hop_interval` |
| Hysteria2 | `pinSHA256`, `pin_sha256` | Certificate pin | `Hysteria2Config.pin_sha256` |
| Hysteria v1 | `protocol`, `type` | Protocol variant | `Hysteria1Config.protocol` |
| Hysteria v1 | `up_mbps`/`upmbps`, `down_mbps`/`downmbps` | Bandwidth, Mbps | `Hysteria1Config.up_mbps`, `.down_mbps` |
| WireGuard | `publickey`/`public_key`, `presharedkey`/`psk` | Peer and pre-shared keys | `WireguardConfig` |
| WireGuard | `address`, `reserved`, `mtu` | Interface fields | `WireguardConfig` |
| WireGuard | `persistent_keepalive`/`keepalive`, `dns`, `remote_dns_resolve`/`remote_dns` | Interface fields | `WireguardConfig` |
| Shadowsocks | `plugin` | SIP003 plugin, name and options in one value | `SsConfig.plugin` |

### 24.4 Upstream format implementations

| Upstream | Dispatch | Parse | Format |
|---|---|---|---|
| v2rayN (C#) | `FmtHandler.cs` | `*Fmt.Resolve(string)` | `*Fmt.ToUri(ProfileItem)` |
| v2rayNG (Kotlin) | `AngConfigManager.kt` `configFmtParsers` | `*Fmt.parse(String)` | `*Fmt.toUri(ProfileItem)` |
| subconverter (C++) | `subparser.cpp` `explode()` by scheme | `explode*(const string&, Proxy&)` | `subexport.cpp` `proxyToSingle()` |
| xray-checker (Go) | `parser.go` `parseShareLink()` | per type | libXray CGO |
| this repo (Rust) | `crates/leas-config/src/import_export.rs` `parse_share_url()` | `ProtocolConfig::try_parse_proto` then each `*Config::try_parse_proto` | `format_share_url()` → `reconstruct_proto` |

v2ray-core and v2ray-core-legacy have no URL parsing at all; they are runtimes, not clients.

### 24.5 Third-party snapshots

| Repository | Path | HEAD commit and subject |
|---|---|---|
| Xray-core | `thirdparty/Xray-core/` | `d7fa207`: Forbid unencrypted outbounds on public Internet for VLESS and Trojan; remove none/zero/plain for VMess and Shadowsocks |
| v2ray-core | `thirdparty/v2ray-core/` | `9db9c4b`: update version to v5.52.0 |
| v2ray-core-legacy | `thirdparty/v2ray-core-legacy/` | `d80440f`: Merge pull request #3085 |
| v2rayN | `thirdparty/v2rayN/` | `ad12a6c`: Update ca cert (#9700) |
| v2rayNG | `thirdparty/v2rayNG/` | `9397a9e`: Fix (#5889) |
| sing-box | `thirdparty/sing-box/` | `0f17638`: Fix v2rayhttp upgrade leak |
| mihomo | `thirdparty/mihomo/` | `2c7309e`: fix: listener duplicate-name check (#2948) |
| quirktiva | `thirdparty/quirktiva/` | `abece1f`: Chore: update test dependencies |
| subconverter | `thirdparty/subconverter/` | `fe6666c`: chore: fix build scripts |
| xray-checker | `thirdparty/xray-checker/` | `f829c2b`: Merge pull request #175 |
| shoes | `thirdparty/shoes/` | `607ccde`: reality: match Chrome signature algorithms |
| leaf | `thirdparty/leaf/` | `1d20301`: Revert "feat(inbound): limit data transfer and concurrent connections per IP" |
| shadowsocks-rust | `thirdparty/shadowsocks-rust/` | `f827f6d`: fix(netbsd): passthrough syntax for RUSTFLAGS in Cross.toml |
| trojan | `thirdparty/trojan/` | `3e7bb9a`: Update CONTRIBUTORS.md |

Refresh these hashes after pulling or re-cloning the submodules.
