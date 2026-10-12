# Clash (mihomo) Profile Configuration Format

> **Audience**: Developers implementing Clash config parsing in `proto_spec`.
> **Status**: Comprehensive reference from mihomo v1.18 and quirktiva codebases.
> **Source repos**: `thirdparty/mihomo/` (mihomo) and `thirdparty/quirktiva/` (quirktiva).

---

## Table of Contents

1. [Overview](#1-overview)
2. [Top-Level YAML Structure](#2-top-level-yaml-structure)
3. [Common Proxy Fields](#3-common-proxy-fields)
4. [Proxy Type Reference](#4-proxy-type-reference)
   - 4.1 vmess
   - 4.2 vless
   - 4.3 trojan
   - 4.4 ss (Shadowsocks)
   - 4.5 ssr (ShadowsocksR)
   - 4.6 socks5
   - 4.7 http
   - 4.8 tuic
   - 4.9 hysteria2
   - 4.10 hysteria (v1)
   - 4.11 wireguard
   - 4.12 snell
   - 4.13 anytls
   - 4.14 ssh
   - 4.15 tailscale
   - 4.16 gost-relay
   - 4.17 direct / dns / reject / rematch
   - 4.18 mieru / sudoku / masque / trusttunnel / openvpn
5. [Proxy Groups](#5-proxy-groups)
6. [Proxy Providers](#6-proxy-providers)
7. [Rules](#7-rules)
8. [Rule Providers](#8-rule-providers)
9. [DNS Configuration](#9-dns-configuration)
10. [TUN Configuration](#10-tun-configuration)
11. [Sniffer Configuration](#11-sniffer-configuration)
12. [Profile / Cache](#12-profile--cache)
13. [General Settings](#13-general-settings)
14. [Shared Sub-Option Types](#14-shared-sub-option-types)
15. [Cross-Reference Table](#15-cross-reference-table)

---

## 1. Overview

Clash/Meta (mihomo) uses **YAML** as its native configuration format. The root `proxies:` key
contains an array of proxy entries, each identified by a `type:` field. The `config/config.go`
`RawConfig` struct defines the entire YAML schema; `adapter/parser.go` `ParseProxy()` dispatches
by `type:` to individual Option structs (tagged with `proxy:`).

quirktiva is a fork of the same Clash codebase with approximately the same format.

---

## 2. Top-Level YAML Structure

```yaml
# ---- General ----
port: 7890
socks-port: 7891
mixed-port: 7892
redir-port: 7893
tproxy-port: 7894
allow-lan: false
bind-address: "0.0.0.0"
mode: rule                  # rule / global / direct / script
log-level: info             # silent / error / warning / info / debug / trace
ipv6: false                 # default false
tcp-concurrent: false       # Concurrent TCP connections
find-process-mode: always   # always / strict / off

# ---- Authentication ----
authentication:
  - "user:pass"
skip-auth-prefixes:         # CIDR ranges that skip auth
  - 127.0.0.1/32
lan-allowed-ips:            # Whitelist for LAN connections
  - 0.0.0.0/0
lan-disallowed-ips:         # Blacklist for LAN connections

# ---- Interface ----
interface-name: eth0
routing-mark: 6666

# ---- External API ----
external-controller: 127.0.0.1:9090
external-controller-tls: 0.0.0.0:8443
external-controller-cors: ["*"]
external-controller-unix: ""
external-controller-routing-mark: 6667
secret: ""
external-ui: /path/to/ui
external-ui-name: dashboard
external-ui-url: "https://github.com/..."

# ---- Geo ----
geox-url:                   # URL overrides for Geo databases
  geoip: "https://..."
  geosite: "https://..."
  mmdb: "https://..."
geo-auto-update: false
geo-update-interval: 24     # hours

# ---- misc ----
global-ua: "clash.meta"
etag-support: false
keep-alive-idle: 15         # TCP keepalive seconds
keep-alive-interval: 15     # seconds
disable-keep-alive: false

# ---- TLS inbounds ----
tls:
  certificate: ./server.crt
  private-key: ./server.key

# ---- Hosts ----
hosts:
  '*.mihomo.dev': 127.0.0.1

# ---- Profile cache ----
profile:
  store-selected: true       # Persist proxy selections across restarts
  store-fake-ip: true        # Persist fake-ip mapping

# ---- TUN ----
tun:
  enable: true
  stack: system             # system / gvisor / mixed

# ---- Sniffer ----
sniffer:
  enable: true

# ---- DNS ----
dns:
  enable: true

# ---- Tunnels ----
tunnels:
  - network: [tcp, udp]
    address: 127.0.0.1:7777
    target: target.com
    proxy: proxy

# ---- Listeners ----
listeners:
  - type: tun               # Additional tun inbounds
    name: tun1
    listen: 1.0.0.1
    ...

# ---- Proxy definitions ----
proxies:
  - name: "my-proxy"
    type: ss
    server: server.com
    port: 443
    cipher: aes-128-gcm
    password: "secret"

# ---- Proxy providers ----
proxy-providers:
  provider1:
    type: http
    url: "https://..."
    interval: 3600

# ---- Proxy groups ----
proxy-groups:
  - name: "proxy"
    type: select
    proxies:
      - my-proxy
      - DIRECT

# ---- Rule providers ----
rule-providers:
  rule1:
    behavior: classical
    type: http
    url: "https://..."

# ---- Rules ----
rules:
  - DOMAIN-SUFFIX,google.com,proxy
  - MATCH,DIRECT

# ---- Sub-rules (Meta feature) ----
sub-rules:
  - name: sub-rule-name
    rules:
      - DOMAIN-KEYWORD,test,proxy2

# ---- Experimental ----
experimental:
  quic-go-disable-gso: false

# ---- NTP ----
ntp:
  enable: false
  server: time.apple.com
  port: 123

# ---- IPTables (Linux) ----
iptables:
  enable: false

# ---- Clash for Android ----
clash-for-android:
  ui-trigger: soft
  client-id: ""
  global-client-fingerprint: chrome
```

---

## 3. Common Proxy Fields

Every proxy entry in `proxies:` shares these top-level YAML keys (from `BasicOption`
in `adapter/outbound/base.go` and the `ParseProxy()` dispatch):

```yaml
- name: "proxy-name"          # Required — unique identifier
  type: "ss"                  # Required — protocol type
  server: "example.com"       # Required — target address/domain
  port: 443                   # Required — target port
  udp: false                  # Optional — default false
  tfo: false                  # Optional — TCP Fast Open
  mptcp: false                # Optional — Multipath TCP
  interface-name: ""          # Optional — bind to interface
  routing-mark: 0             # Optional — Linux fwmark
  ip-version: dual            # Optional — dual / ipv4 / ipv6 / ipv4-prefer / ipv6-prefer
  dialer-proxy: ""            # Optional — route through another proxy
  prefer: dual                # Optional — DNS prefer (dual / ipv4 / ipv6)
  client-fingerprint: ""      # Optional — uTLS fingerprint for TLS proxies

  # Multiplex (smux) — can wrap ANY proxy type
  smux:
    enabled: false
    protocol: smux             # smux / yamux / h2mux
    max-connections: 0
    min-streams: 0
    max-streams: 0
    padding: false
    statistic: false
    only-tcp: false
```

Additionally, certain proxy types support the old `plugin:` / `plugin-opts:` pattern
(Shadowsocks) and TLS-sensitive `fingerprint:` / `client-fingerprint:` distinction:

- `fingerprint:` — SSL Pinning (cert SHA-256 string)
- `client-fingerprint:` — uTLS Client Hello style for TLS fingerprint spoofing.
  Values: `chrome`, `firefox`, `safari`, `ios`, `random`, `none`.

---

## 4. Proxy Type Reference

### 4.1 `vmess`

**Source**: `adapter/outbound/vmess.go` — `VmessOption` / `VmessOptionAll`

```yaml
- name: "vmess"
  type: vmess
  server: server
  port: 443
  uuid: "uuid"
  alterId: 32                   # Required for VMess — must be 0 in AEAD-only mode
  cipher: auto                  # auto / aes-128-gcm / chacha20-poly1305 / none / zero
  udp: false

  # Network / Transport
  network: tcp                  # tcp / ws / grpc / h2 / http / mkcp / mekya / quic
  tls: true                     # TLS enable
  servername: example.com       # TLS SNI (priority over ws-opts.headers.Host)
  skip-cert-verify: false
  alpn: [h2, http/1.1]
  fingerprint: ""               # SSL Pinning
  client-fingerprint: chrome    # uTLS fingerprint

  # ECH
  ech-opts:
    enable: true
    config: "base64-ech-config"
    query-server-name: "domain.com"

  # TLS Mirror (mihomo-specific VMess feature)
  tlsmirror-opts:
    primary-key: "base64-32byte"
    explicit-nonce-ciphersuites: [156, ...]
    sequence-watermarking-enabled: false
    embedded-traffic-generator:
      steps:
        - host: example.com
          path: /
          method: GET

  # Transport: WebSocket
  network: ws
  ws-opts:
    path: "/path"
    headers:
      Host: v2ray.com
    max-early-data: 2048
    early-data-header-name: Sec-WebSocket-Protocol
    v2ray-http-upgrade: false      # Enable v2fly HTTPUpgrade over WS
    v2ray-http-upgrade-fast-open: false

  # Transport: gRPC
  network: grpc
  grpc-opts:
    grpc-service-name: "example"
    grpc-user-agent: "grpc-go/1.36.0"
    ping-interval: 0               # Seconds
    max-connections: 1
    min-streams: 0
    max-streams: 0

  # Transport: HTTP/2 (h2)
  network: h2
  h2-opts:
    host:
      - http.example.com
    path: /

  # Transport: HTTP (old — h2 alias)
  network: http
  http-opts:
    method: "GET"
    path:
      - '/'
      - '/video'
    headers:
      Connection:
        - keep-alive

  # Transport: mKCP
  network: mkcp
  mkcp-opts:
    mtu: 1350
    tti: 50
    uplink-capacity: 5
    downlink-capacity: 20
    congestion: false
    write-buffer: 2097152
    read-buffer: 2097152
    seed: ""
    header: none                  # none / srtp / utp / wechat-video / dtls / wireguard

  # Transport: MeKya (mihomo-specific pseudostreaming)
  network: mekya
  tls: true                       # MeKya requires TLS
  mekya-opts:
    url: https://server:443/mekya
    max-write-delay: 80
    max-request-size: 96000
    polling-interval-initial: 200
    h2-pool-size: 8
    kcp:
      mtu: 1350
      tti: 15
      uplink-capacity: 40
      downlink-capacity: 2000

  # REALITY (should use VLESS for REALITY, but some relays may configure)
  reality-opts:
    public-key: "xxx"
    short-id: "xxx"
```

### 4.2 `vless`

**Source**: `adapter/outbound/vless.go` — `VlessOption`

```yaml
- name: "vless"
  type: vless
  server: server
  port: 443
  uuid: "uuid"

  network: tcp                  # tcp / ws / grpc / xhttp
  tls: true
  udp: false
  flow: "xtls-rprx-vision"     # XTLS flow control
  encryption: ""                # vless encryption: native/xorpub/random + x25519/mlkem768
  servername: example.com       # TLS SNI
  skip-cert-verify: false
  alpn: [h2, http/1.1]
  client-fingerprint: chrome

  # REALITY
  reality-opts:
    public-key: "xxx"
    short-id: "xxx"
    support-x25519mlkem768: false

  # ECH
  ech-opts:
    enable: true
    config: "..."

  # Transport: WebSocket
  network: ws
  ws-opts:                      # Same as vmess ws-opts

  # Transport: gRPC
  network: grpc
  grpc-opts:                    # Same as vmess grpc-opts

  # Transport: XHTTP (mihomo-specific)
  network: xhttp
  xhttp-opts:
    path: "/"
    max-download-size: 0
    early-data-header: Sec-WebSocket-Protocol
    reuse:                      # Reuse HTTP connection
      enabled: true
      extra-path: "/reuse"
```
  
**How transport options are stored in the Go struct** (vs our proto_spec):

| Field | mihomo struct | YAML key |
|-------|--------------|----------|
| WS path | `WSOptions.Path` | `ws-opts.path` |
| WS headers | `WSOptions.Headers` | `ws-opts.headers` |
| WS max-early-data | `WSOptions.MaxEarlyData` | `ws-opts.max-early-data` |
| WS early-data-header | `WSOptions.EarlyDataHeaderName` | `ws-opts.early-data-header-name` |
| WS http-upgrade | `WSOptions.V2rayHttpUpgrade` | `ws-opts.v2ray-http-upgrade` |
| WS http-upgrade fast-open | `WSOptions.V2rayHttpUpgradeFastOpen` | `ws-opts.v2ray-http-upgrade-fast-open` |
| gRPC service name | `GrpcOptions.GrpcServiceName` | `grpc-opts.grpc-service-name` |
| gRPC user-agent | `GrpcOptions.GrpcUserAgent` | `grpc-opts.grpc-user-agent` |
| gRPC ping interval | `GrpcOptions.PingInterval` | `grpc-opts.ping-interval` |
| XHTTP path | `XHTTPOptions.Path` | `xhttp-opts.path` |
| XHTTP reuse | `XHTTPOptions.Reuse` | `xhttp-opts.reuse` |

### 4.3 `trojan`

**Source**: `adapter/outbound/trojan.go` — `TrojanOption`

```yaml
- name: "trojan"
  type: trojan
  server: server
  port: 443
  password: "yourpsk"
  udp: false
  tls: true                     # Trojan always has TLS
  flow: "xtls-rprx-direct"     # Optional XTLS flow
  flow-show: true               # Display flow info
  sni: example.com
  alpn: [h2, http/1.1]
  skip-cert-verify: false
  client-fingerprint: chrome
  fingerprint: ""               # SSL Pinning

  # Trojan-Go Shadowsocks overlay
  ss-opts:
    enabled: false
    method: aes-128-gcm
    password: "example"

  # ECH
  ech-opts:
    enable: true
    config: "..."

  # Transport (non-TCP)
  network: ws                   # ws / grpc
  ws-opts: ...
  grpc-opts: ...
```

**Trojan-specific vs our proto_spec**:
- Trojan-Go SS overlay (`ss-opts`) — not in our proto_spec
- `flow-show` — not in our proto_spec
- `trojan` uses `password:` not TLS-based auth

### 4.4 `ss` (Shadowsocks)

**Source**: `adapter/outbound/shadowsocks.go` — `ShadowSocksOption`

```yaml
- name: "ss1"
  type: ss
  server: server
  port: 443
  cipher: chacha20-ietf-poly1305
  password: "password"
  udp: false
  udp-over-tcp: false           # UDP over TCP fallback

  # SIP003 Plugin (simple-obfs / v2ray-plugin / shadow-tls / restls / kcptun / gost-plugin)
  plugin: obfs                  # obfs / v2ray-plugin / shadow-tls / restls / kcptun
  plugin-opts:
    mode: tls                   # tls / http / websocket / shadow-tls
    host: bing.com
    password: "shadow_tls_pwd"  # for shadow-tls plugin
    version: 2                  # for shadow-tls plugin
    alpn: ["h2","http/1.1"]     # for shadow-tls plugin
    tls: true                   # for v2ray-plugin wss
    fingerprint: "..."          # SSL pinning
    skip-cert-verify: true
    path: "/"
    mux: false
    headers:
      custom: value
    v2ray-http-upgrade: false
    v2ray-http-upgrade-fast-open: false
    # kcptun-specific plugin-opts:
    key: "pre-shared-secret"
    crypt: aes                  # aes, aes-128, salsa20, etc.
    mode: fast                  # fast3 / fast2 / fast / normal / manual
    mtu: 1350
    sndwnd: 128
    rcvwnd: 512
    datashard: 10
    parityshard: 3
    nocomp: false
    nodelay: 0
    interval: 50
    # ... (extensive KCP tuning)

  # Restls-specific plugin
  plugin: restls
  plugin-opts:
    host: "www.microsoft.com"
    password: "restls-password"
    version-hint: "tls13"       # tls13 / tls12
    restls-script: "300?100<1,400~100,..."
```

**Key differences from our proto_spec**:
- `plugin` and `plugin-opts` are standard (our proto_spec SsConfig lacks them)
- `udp-over-tcp` — not in our proto_spec
- Plugin options are a free-form map (not typed) — mihomo uses generic `map[string]any`

### 4.5 `ssr` (ShadowsocksR)

**Source**: `adapter/outbound/shadowsocksr.go` — `ShadowSocksROption`

```yaml
- name: "ssr"
  type: ssr
  server: server
  port: 443
  cipher: aes-256-cfb
  password: "password"
  protocol: auth_aes128_md5
  protocol-param: ""
  obfs: tls1.2_ticket_auth
  obfs-param: ""
  udp: false
```

### 4.6 `socks5`

**Source**: `adapter/outbound/socks5.go` — `Socks5Option`

```yaml
- name: "socks"
  type: socks5
  server: server
  port: 443
  username: ""
  password: ""
  tls: false
  udp: false
  skip-cert-verify: false
  fingerprint: ""
  # mTLS:
  certificate: ./client.crt
  private-key: ./client.key
```

### 4.7 `http`

**Source**: `adapter/outbound/http.go` — `HttpOption`

```yaml
- name: "http"
  type: http
  server: server
  port: 443
  username: ""
  password: ""
  tls: false                     # HTTPS when true
  sni: custom.com
  skip-cert-verify: false
  fingerprint: ""
  # mTLS:
  certificate: ./client.crt
  private-key: ./client.key
  headers:                       # Additional headers
    custom: "value"
```

### 4.8 `tuic`

**Source**: `adapter/outbound/tuic.go` — `TuicOption`

```yaml
- name: "tuic"
  type: tuic
  server: server
  port: 443
  token: "your_token"            # TUIC auth (uuid:password in URL format)
  ip: 127.0.0.1
  udp: true
  heartbeat-interval: 10000
  reduce-rtt: false
  request-timeout: 8000
  max-udp-relay-packet-size: 1500
  fast-open: true
  max-open-streams: 100
  congestion-controller: bbr     # cubic / bbr / new_reno / bbr3
  cwnd: 10                       # Initial congestion window
  bbr-profile: standard          # standard / conservative / aggressive
  receive-window-conn: 12582912
  receive-window: 52428800
  disable-mtu-discovery: false
  max-datagram-frame-size: 1500
  udp-relay-mode: native         # native / quic

  # QUIC tuning
  initial-stream-receive-window: 8388608
  max-stream-receive-window: 8388608
  initial-connection-receive-window: 20971520
  max-connection-receive-window: 20971520

  # TLS
  sni: example.com
  skip-cert-verify: false
  fingerprint: ""
  alpn: [h3]

  # ECH
  ech-opts:
    enable: true
    config: "..."
```

**Key differences from our proto_spec**:
- `token` vs our `uuid:password` — mihomo stores as single token string
- Extensive QUIC tuning params not in our proto_spec
- `reduce-rtt`, `max-open-streams`, `cwnd`, `bbr-profile`, etc.

### 4.9 `hysteria2`

**Source**: `adapter/outbound/hysteria2.go` — `Hysteria2Option`

```yaml
- name: "hysteria2"
  type: hysteria2
  server: server.com
  port: 443
  ports: 1000,2000-3000          # Port hopping (comma/range)
  hop-interval: 15                # Port hopping interval, seconds
  up: "30 Mbps"                   # Bandwidth limit (string with unit)
  down: "200 Mbps"                # If empty, use BBR flow control
  password: "yourpassword"
  obfs: salamander                # salamander / gecko
  obfs-password: "yourpassword"
  obfs-min-packet-size: 512       # Gecko only
  obfs-max-packet-size: 1200      # Gecko only
  bbr-profile: standard           # standard / conservative / aggressive

  sni: server.com
  skip-cert-verify: false
  fingerprint: ""
  alpn: [h3]

  # ECH
  ech-opts:
    enable: true
    config: "..."

  # Realm (mihomo-specific)
  realm-opts:
    enable: true
    server-url: https://realm.hy2.io
    token: public
    realm-id: my-cabin-1f3a8c2e9b
    stun-servers:
      - stun.nextcloud.com:3478

  # QUIC tuning
  initial-stream-receive-window: 8388608
  max-stream-receive-window: 8388608
  initial-connection-receive-window: 20971520
  max-connection-receive-window: 20971520
```

**Key differences from our proto_spec**:
- Bandwidth `up/down` as strings (e.g., `"30 Mbps"`, `"50 M"`) — our proto_spec stores as raw strings
- `bbr-profile` — not in our proto_spec
- `realm-opts` — mihomo-specific
- Extensive QUIC tuning params
- `ports` vs our `PortSpec` (same concept)

### 4.10 `hysteria` (v1)

**Source**: `adapter/outbound/hysteria.go` — `HysteriaOption`

```yaml
- name: "hysteria"
  type: hysteria
  server: server.com
  port: 443
  ports: 1000,2000-3000          # Port hopping
  auth-str: "yourpassword"       # Authentication string
  auth: ""                       # Authentication bytes (alternative)
  obfs: "obfs_str"
  alpn: [h3]
  protocol: udp                  # udp / wechat-video / faketcp
  up: "30 Mbps"
  down: "200 Mbps"
  sni: server.com
  skip-cert-verify: false
  fingerprint: ""
  recv-window-conn: 12582912
  recv-window: 52428800
  disable-mtu-discovery: false
  fast-open: true

  # ECH
  ech-opts:
    enable: true
    config: "..."
```

### 4.11 `wireguard`

**Source**: `adapter/outbound/wireguard.go` — `WireGuardOption`

```yaml
- name: "wg"
  type: wireguard
  server: 162.159.192.1
  port: 2480
  ip: 172.16.0.2                 # Interface IPv4 address
  ipv6: fd01:...                 # Interface IPv6 address
  private-key: "base64-private-key"
  public-key: "base64-public-key"
  pre-shared-key: "base64-psk"
  udp: true
  reserved: "U4An"               # Reserved bytes (string or array)
  # reserved: [209,98,59]
  mtu: 1400
  persistent-keepalive: 0
  dns:                           # DNS servers when remote-dns-resolve is true
    - 1.1.1.1
    - 8.8.8.8
  remote-dns-resolve: false      # Force remote DNS resolution
  refresh-server-ip-interval: 60 # Seconds

  # Multi-peer (optional)
  peers:
    - server: 162.159.192.1
      port: 2480
      public-key: "base64-key"
      pre-shared-key: "base64-psk"
      allowed-ips: ['0.0.0.0/0']
      reserved: [209,98,59]

  # AmneziaWG (optional)
  amnezia-wg-option:
    jc: 5
    jmin: 500
    jmax: 501
    s1: 30
    s2: 40
    s3: 50
    s4: 5
    h1: 123456
    h2: 67543
    h3: 123123
    h4: 32345
    i1: "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10><wt 10>"
    i2: "<b 0xf6ab3267fa><r 100>"
    i3: ""
    i4: ""
    i5: ""
    j1: "<b 0xffffffff><c><b 0xf6ab><t><r 10>"
    j2: "<c><b 0xf6ab><t><wt 1000>"
    j3: "<t><b 0xf6ab><c><r 10>"
    itime: 60

  # dialer-proxy applies here too:
  dialer-proxy: "ss1"
```

**Key differences from our proto_spec**:
- Multi-peer via `peers[]` array
- `persistent-keepalive` — not in our proto_spec
- `remote-dns-resolve` + `dns` — not in our proto_spec
- `refresh-server-ip-interval` — not in our proto_spec
- AmneziaWG — not in our proto_spec
- `ip` as dedicated field (vs our `address` for CIDR)
- `ipv6` as separate from `ip`

### 4.12 `snell`

**Source**: `adapter/outbound/snell.go` — `SnellOption`

```yaml
- name: "snell"
  type: snell
  server: server
  port: 44046
  psk: "yourpsk"
  version: 4                      # 1 / 2 / 3 / 4 / 5
  udp: false
  reuse: false                    # v4/5 only
  obfs-opts:
    mode: http                    # http / tls / shadow-tls
    host: bing.com
    password: "shadow_tls_password"
    version: 2
    alpn: ["h2","http/1.1"]
  client-fingerprint: chrome
```

### 4.13 `anytls`

**Source**: `adapter/outbound/anytls.go` — `AnyTLSOption`

```yaml
- name: "anytls"
  type: anytls
  server: server
  port: 443
  password: "password"
  udp: false

  sni: example.com
  alpn: [h2, http/1.1]
  skip-cert-verify: false
  fingerprint: ""
  client-fingerprint: chrome

  idle-session-check-interval: 30  # Seconds
  idle-session-timeout: 60         # Seconds
  min-idle-session: 0
```

**Key differences from our proto_spec**:
- `idle-session-check-interval`, `idle-session-timeout`, `min-idle-session` — not in our placeholder

### 4.14 `ssh`

**Source**: `adapter/outbound/ssh.go` — `SshOption`

```yaml
- name: "ssh"
  type: ssh
  server: server
  port: 22
  user: "username"
  password: "password"
  private-key: "---BEGIN---\n..."
  private-key-path: "~/.ssh/id_rsa"
  private-key-passphrase: ""
  host-key: []
  host-key-algorithms: []
  client-version: ""
```

### 4.15 `tailscale`

**Source**: `adapter/outbound/tailscale.go` — `TailscaleOption`

```yaml
- name: "tailscale"
  type: tailscale
  hostname: "mihomo"
  auth-key: "tskey-auth-xxx"
  control-url: https://controlplane.tailscale.com
  state-dir: ./tailscale
  ephemeral: false
  udp: true
  accept-routes: false
  exit-node: 100.64.0.1
  exit-node-allow-lan-access: false
```

### 4.16 `gost-relay`

**Source**: `adapter/outbound/gost_relay.go` — `GostRelayOption`

```yaml
- name: "gost-relay"
  type: gost-relay
  server: relay.example.com
  port: 443
  udp: true
  tls: true                      # Relay + TLS (mutual)
  mux: true                      # Relay + mTLS (when tls also true)
  forward: false                 # Forward mode (server chooses target)
  sni: relay.example.com
  username: "user"
  password: "pass"
  client-fingerprint: chrome
  fingerprint: ""
  skip-cert-verify: false
```

### 4.17 `direct` / `dns` / `reject` / `rematch`

**Source**: `adapter/outbound/direct.go`, `adapter/outbound/dns.go`, `adapter/outbound/reject.go`

```yaml
- name: "direct"
  type: direct                    # No config required beyond name

- name: "dns"
  type: dns                       # No config required

- name: "reject"
  type: reject                    # No config required

- name: "rematch"
  type: rematch                   # Re-evaluates rules
  proxies: []                     # Proxies to test (rematch group)
```

### 4.18 `mieru` / `sudoku` / `masque` / `trusttunnel` / `openvpn`

**Source**: respective files in `adapter/outbound/`

```yaml
- name: "mieru"
  type: mieru
  server: server
  port: 443
  password: "password"
  # mieru uses its own obfuscation protocol

- name: "sudoku"
  type: sudoku
  server: server
  port: 443
  password: "password"
  http-mask-opts:
    headers: {}

- name: "masque"
  type: masque
  server: server
  port: 443
  password: ""
  tls: true

- name: "trusttunnel"
  type: trusttunnel
  server: server
  port: 443
  password: ""

- name: "openvpn"
  type: openvpn
  server: server
  port: 443
```

---

## 5. Proxy Groups

**Source**: `adapter/outboundgroup/groupbase.go` — `GroupBaseOption`
**Parser**: `adapter/outboundgroup/parser.go` — `GroupCommonOption`

Proxy groups are defined in the `proxy-groups:` YAML array. All groups share:

```yaml
proxy-groups:
  - name: "auto"                 # Required — unique name
    type: url-test               # select / url-test / fallback / load-balance / relay
    proxies:                     # Inline proxy names
      - ss1
      - ss2
    use:                         # Proxy provider references
      - provider1
    url: "https://cp.cloudflare.com/generate_204"
    interval: 300                # Health check interval (seconds)
    tolerance: 150               # URLTest: latency tolerance (ms)
    lazy: true                   # Lazy health check
    expected-status: 204         # Expected HTTP status code
    disable-udp: false           # Disable UDP for this group
    filter: "HK|TW"              # Regex filter for provider proxies
    default-selected: "ss1"      # Select group only — default choice
    empty-fallback: COMPATIBLE   # Fallback when group is empty
    hidden: false                # Hide from API endpoints
    icon: "https://..."          # Group icon URL

  # Load-balance additional
  - name: "load-balance"
    type: load-balance
    strategy: consistent-hashing  # round-robin / consistent-hashing / sticky-sessions
```

### Group Type Behavior

| Type | Behavior | Extra Config |
|------|----------|-------------|
| `select` | Manual selection | `default-selected` |
| `url-test` | Auto-picks lowest latency | `tolerance`, `lazy`, `expected-status` |
| `fallback` | Picks first alive proxy | `lazy`, `expected-status` |
| `load-balance` | Distributes across proxies | `strategy` |
| `relay` | Chain proxies sequentially | Order from `proxies:` list |

---

## 6. Proxy Providers

**Source**: `adapter/provider/parser.go` — `proxyProviderSchema`
**Field**: `config/config.go` `RawProvider`

Proxy providers define external proxy sources. The parsed result feeds into
`CompatibleProvider` (for empty use), `ProxySetProvider` (file/http), or
`InlineProvider` (inline payload).

```yaml
proxy-providers:
  provider1:
    type: http                    # http / file / inline
    url: "https://example.com/sub"
    interval: 3600                # Refresh interval (seconds)
    path: ./provider1.yaml        # Cache path (relative to home dir)
    proxy: DIRECT                 # Download through specified proxy
    size-limit: 10240             # Max download size (bytes)
    age-secret-key: "AGE-SECRET-KEY-..."  # Age decryption key

    # HTTP headers
    header:
      User-Agent:
        - "Clash/v1.18.0"
        - "mihomo/1.18.3"

    # Health check for provider proxies
    health-check:
      enable: true
      interval: 600
      lazy: true
      url: https://cp.cloudflare.com/generate_204
      expected-status: 204

    # Override fields for all proxies from this provider
    override:
      skip-cert-verify: true
      udp: true
      down: "50 Mbps"
      up: "10 Mbps"
      dialer-proxy: proxy
      interface-name: tailscale0
      routing-mark: 233
      ip-version: ipv4-prefer
      additional-prefix: "[provider1]"
      additional-suffix: "test"
      proxy-name:
        - pattern: "test"
          target: "TEST"

  # Inline provider — proxies defined directly
  provider2:
    type: inline
    dialer-proxy: proxy
    payload:
      - name: "ss1"
        type: ss
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: "password"

  # File provider — reads from local YAML
  test:
    type: file
    path: /test.yaml
    health-check:
      enable: true
      interval: 36000
      url: https://cp.cloudflare.com/generate_204
```

### Provider Types

| Type | Description | Vehicle |
|------|-------------|---------|
| `http` | Fetch from URL, cache to `path` | `HTTPVehicle` |
| `file` | Read from local file | `FileVehicle` |
| `inline` | Inline YAML payload | N/A (embedded) |

### Provider Override Fields

| Field | Type | Description |
|-------|------|-------------|
| `skip-cert-verify` | `bool` | Override TLS verify |
| `udp` | `bool` | Override UDP support |
| `down` | `string` | Override download bandwidth |
| `up` | `string` | Override upload bandwidth |
| `dialer-proxy` | `string` | Route through another proxy |
| `interface-name` | `string` | Bind to interface |
| `routing-mark` | `int` | Set routing mark |
| `ip-version` | `string` | IP version preference |
| `additional-prefix` | `string` | Prefix to proxy names |
| `additional-suffix` | `string` | Suffix to proxy names |
| `proxy-name` | `[]PatternTarget` | Regex name replacement |

---

## 7. Rules

**Source**: `rules/parser.go` — `ParseRule()`
**All rule types**: `rules/common/*.go` and `rules/logic/logic.go`

### Rule Format

```
<RULETYPE>,<value>,<policy>[,no-resolve]
```

- `<policy>` references a proxy name, proxy group name, `DIRECT`, `REJECT`,
  `REJECT-DROP`, `PASS`, or `COMPATIBLE`
- `no-resolve` — skip DNS resolution for IP-based matching on domain traffic

### Rule Types

| Rule Type | Value | Description |
|-----------|-------|-------------|
| `DOMAIN` | exact domain | Exact domain match |
| `DOMAIN-SUFFIX` | suffix | Domain suffix (with leading dot) |
| `DOMAIN-KEYWORD` | substring | Domain keyword substring |
| `DOMAIN-REGEX` | regex pattern | Regex on domain |
| `DOMAIN-WILDCARD` | wildcard | Wildcard (`*.example.com`, `*test*`) |
| `GEOIP` | country code | GeoIP country match |
| `SRC-GEOIP` | country code | Source GeoIP country |
| `GEOSITE` | category | Geosite category |
| `IP-CIDR` | CIDR | Destination IP CIDR |
| `IP-CIDR6` | IPv6 CIDR | IPv6 destination CIDR |
| `SRC-IP-CIDR` | CIDR | Source IP CIDR |
| `SRC-IP-ASN` | ASN number | Source ASN match |
| `IP-ASN` | ASN number | Destination ASN match |
| `IP-SUFFIX` | IP suffix | Destination IP suffix bytes |
| `SRC-IP-SUFFIX` | IP suffix | Source IP suffix bytes |
| `SRC-PORT` | port/range | Source port |
| `DST-PORT` | port/range | Destination port |
| `IN-PORT` | port/range | Inbound listener port |
| `PROCESS-NAME` | name | Process name match |
| `PROCESS-PATH` | path | Process path match |
| `PROCESS-NAME-REGEX` | regex | Process name regex |
| `PROCESS-PATH-REGEX` | regex | Process path regex |
| `PROCESS-NAME-WILDCARD` | wildcard | Process name wildcard |
| `PROCESS-PATH-WILDCARD` | wildcard | Process path wildcard |
| `NETWORK` | `tcp`/`udp` | Network protocol |
| `UID` | user ID | Linux user ID |
| `DSCP` | DSCP value | Differentiated Services Code Point |
| `IN-TYPE` | inbound type | `HTTP`/`SOCKS5`/`TUN`/`REDIR`/`TPROXY` |
| `IN-USER` | username | Inbound authenticated user |
| `IN-NAME` | listener name | Inbound listener name |
| `REMATCH-NAME` | name | Re-evaluate rules by name |
| `AND` | `(rule1,rule2,...)` | Logical AND of sub-rules |
| `OR` | `(rule1,rule2,...)` | Logical OR of sub-rules |
| `NOT` | `(rule)` | Logical NOT of a rule |
| `SUB-RULE` | rule set name | Evaluate named sub-rule set |
| `RULE-SET` | provider name | Evaluate rule set from provider |
| `MATCH` | (none) | Final catch-all rule |

### Sub-Rules

```yaml
sub-rules:
  - name: "sub-rule-name"
    rules:
      - DOMAIN-KEYWORD,test,proxy2
```

---

## 8. Rule Providers

**Source**: `rules/provider/parse.go` — `ParseRuleProvider`

```yaml
rule-providers:
  rule1:
    behavior: classical           # domain / ipcidr / classical
    interval: 259200              # Refresh interval (seconds)
    path: /path/to/save/file.yaml # Cache path
    type: http                    # http / file / inline
    url: "https://..."
    proxy: DIRECT                 # Download proxy
    format: yaml                  # yaml / text / mrs
    size-limit: 0                 # Max download size
    # For `inline` type:
    payload: |
      - DOMAIN-SUFFIX,google.com,proxy
    # For `classical` behavior:
    payload:
      - 'DOMAIN-SUFFIX,google.com,proxy'
```

### Behavior Types

| Behavior | Payload Format | Rule Types Used |
|----------|---------------|-----------------|
| `domain` | Simple domain list | Realized as DOMAIN or DOMAIN-SUFFIX |
| `ipcidr` | CIDR list | Realized as IP-CIDR |
| `classical` | Full rule syntax | All rule types |

### Format Types

| Format | Description |
|--------|-------------|
| `yaml` | YAML array of rule strings |
| `text` | Plain text, one rule per line |
| `mrs` | Binary mihomo rule set format |

---

## 9. DNS Configuration

**Source**: `config/config.go` — `RawDNS` struct

```yaml
dns:
  enable: false
  prefer-h3: false                          # DoH HTTP/3 support
  listen: 0.0.0.0:53
  ipv6: false                               # Return empty AAAA when false
  use-system-hosts: false                   # /etc/hosts resolution
  use-system-nameservers: false             # /etc/resolv.conf fallback
  use-dns-hijacking: false                  # Capture system DNS queries
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:                           # Skip fake-ip for these domains
    - '+.lan'
    - '+.local'
    - 'dns.msftncsi.com'
  fake-ip-filter-mode: blacklist            # blacklist / whitelist
  enhanced-mode: fake-ip                    # fake-ip / redir-host / normal / hosts
  sniffing: false                           # DNS response sniffing for accurate domain capture
  strict-mode: false                        # Return SERVFAIL on non-standard query
  cache-algorithm: arc                      # lru / lfu / arc / clock
  nameserver:                               # Primary DNS servers
    - https://dns.alidns.com/dns-query
    - 223.5.5.5
  fallback:                                 # Fallback DNS servers
    - tls://8.8.4.4:853
  fallback-filter:
    geoip: true                             # Filter results by GeoIP
    geoip-code: CN                          # Use fallback if result is in this country
    geosite: ['cn']                         # Use fallback if geosite matches
    ip-cidr:                                # Use fallback if IP matches
      - 240.0.0.0/4
  nameserver-policy:                        # Per-domain DNS overrides
    "geosite:cn,dns": 8.8.8.8
    "rule-set:global,dns": 8.8.8.8
    "www.baidu.com": 114.114.114.114
  proxy-server-nameserver:                  # DNS for proxy server domains
    - https://dns.alidns.com/dns-query
  direct-nameserver:                        # DNS for direct outbound
    - https://dns.alidns.com/dns-query
  direct-nameserver-follow-policy: false    # Follow nameserver-policy for direct
  search-domains:
    - local.domain
```

---

## 10. TUN Configuration

**Source**: `config/config.go` — `RawTun` struct

```yaml
tun:
  enable: false
  stack: system                 # system / gvisor / mixed
  device-url: utun://tun0       # Platform-specific TUN device URL
  dns-hijack:
    - 0.0.0.0:53
  auto-detect-interface: true   # Auto-detect default route interface
  auto-route: true              # Configure routing table
  mtu: 9000
  gso: false                    # Generic Segmentation Offload (Linux)
  gso-max-size: 65536
  auto-redirect: false          # Auto iptables redirect (Linux)
  strict-route: true            # Route all connections to TUN
  disable-icmp-forwarding: true # Prevent ICMP loopback
  route-address-set:            # Rulesets for firewall routes
    - ruleset-1
  route-exclude-address-set:
    - ruleset-3
  route-address:                # Custom routes
    - 0.0.0.0/1
  inet4-route-address:
    - 0.0.0.0/1
  inet6-route-address:
    - "::/1"
  endpoint-independent-nat: false
  include-interface:
    - lan0
  exclude-interface:
    - lan1
  include-uid:                  # Linux only
    - 0
  include-uid-range:
    - 1000:9999
  exclude-uid:
    - 1000
  exclude-uid-range:
    - 0:999
  include-mac-address:
    - 00:11:22:33:44:55
  exclude-mac-address:
    - 00:11:22:33:44:56
  # Android
  include-android-user:
    - 0
  include-package:
    - com.android.chrome
  exclude-package:
    - com.android.captiveportallogin
```

---

## 11. Sniffer Configuration

**Source**: `config/config.go` — `RawSniffer` struct

```yaml
sniffer:
  enable: false
  force-dns-mapping: false              # Force sniff redir-host traffic
  parse-pure-ip: false                  # Sniff all undetermined traffic
  override-destination: true            # Use sniffed domain as destination

  sniff:                                # Per-protocol configuration
    TLS:                                 # Default port 443
      ports: [443, 8443]
    HTTP:                                # Default port 80
      ports: [80, 8080-8880]
      override-destination: true
    QUIC:
    # ports: [ 443 ]

  force-domain:                         # Always sniff these domains
    - +.v2ex.com
  skip-src-address:                     # Skip sniffing by src IP
    - 192.168.0.3/32
  skip-dst-address:                     # Skip sniffing by dst IP
    - 192.168.0.3/32
  skip-domain:                          # Skip sniffing by snooped domain
    - Mijia Cloud
```

---

## 12. Profile / Cache

**Source**: `component/profile/profile.go`, `component/profile/cachefile/cache.go`

```yaml
profile:
  store-selected: true      # Persist manual proxy selections (bbolt DB)
  store-fake-ip: true       # Persist fake-ip mappings
```

The `CacheFile` uses **bbolt** DB stored at `$HOME/.config/clash/cache.db` with buckets:
- `selected` — Selected proxy per group
- `fakeip` — Fake IP → domain mapping
- `etag` — HTTP ETags for provider downloads
- `subscriptioninfo` — Subscription upload/download/total/expire from `Subscription-Userinfo` header
- `storage` — Generic key-value storage

---

## 13. General Settings

**Source**: `config/config.go` — `RawGeneral`, `General`, `Inbound`

```yaml
# Mixed port (socks + http on same port)
mixed-port: 7892

# Inbound sockets
socks-port: 7891              # SOCKS5 proxy port
port: 7890                    # HTTP proxy port
redir-port: 7893              # Redirect proxy port (iptables)
tproxy-port: 7894             # TProxy port (Linux only)

# Mode
mode: rule                    # rule / global / direct / script

# Logging
log-level: info               # silent / error / warning / info / debug / trace

# LAN access
allow-lan: false
bind-address: "0.0.0.0"
lan-allowed-ips:              # LAN access whitelist
  - 0.0.0.0/0
lan-disallowed-ips:           # LAN access blacklist

# Authentication
authentication:
  - "user:password"
skip-auth-prefixes:           # CIDRs that skip authentication
  - 127.0.0.1/32

# IP version
ipv6: false

# TCP tuning
tcp-concurrent: false
find-process-mode: always     # always / strict / off

# Interface
interface-name: eth0
routing-mark: 6666

# Geo
geo-auto-update: false
geo-update-interval: 24       # hours
geox-url:
  geoip: "https://..."
  geosite: "https://..."
  mmdb: "https://..."

# External controller (API)
external-controller: 127.0.0.1:9090
external-controller-tls: 0.0.0.0:8443
external-controller-cors: ["*"]
secret: ""
external-ui: /path/to/ui
external-ui-name: dashboard
external-ui-url: "https://github.com/MetaCubeX/metacubexd"

# SSL inbound cert
tls:
  certificate: ./server.crt
  private-key: ./server.key

# Experimental
experimental:
  quic-go-disable-gso: false
  sniffer-tls-conn: false     # Sniff TLS ClientHello

# NTP
ntp:
  enable: false
  server: time.apple.com
  port: 123

# IPTables (Linux only)
iptables:
  enable: false
  inbound-ports: []
```

---

## 14. Shared Sub-Option Types

### 14.1 ECH Options

```yaml
ech-opts:
  enable: true
  config: "base64-encoded-ech-config"
  query-server-name: "domain.com"
```

### 14.2 REALITY Options

```yaml
reality-opts:
  public-key: "base64-public-key"
  short-id: "hex-short-id"
  support-x25519mlkem768: false
```

### 14.3 Smux (Multiplex) Options

Applied to ANY proxy type as a sub-key:

```yaml
smux:
  enabled: false
  protocol: smux               # smux / yamux / h2mux
  max-connections: 4           # Conflicts with max-streams
  min-streams: 4               # Conflicts with max-streams
  max-streams: 0               # Conflicts with max-connections
  padding: false
  statistic: false
  only-tcp: false
  # Brutal congestion control
  brutal:
    enabled: false
    up-speed: 0                # Mbps
    down-speed: 0              # Mbps
```

### 14.4 `ip-version` Values

| Value | Behavior |
|-------|----------|
| `dual` | Both IPv4 and IPv6 (default) |
| `ipv4` | IPv4 only |
| `ipv6` | IPv6 only |
| `ipv4-prefer` | Prefer IPv4, fall back to IPv6 |
| `ipv6-prefer` | Prefer IPv6, fall back to IPv4 |

---

## 15. Cross-Reference Table

### Source Code Map

| Config Section | File in mihomo | File in quirktiva |
|---------------|----------------|--------------------|
| RawConfig (top-level) | `config/config.go` | `config/config.go` |
| Proxy dispatch | `adapter/parser.go` | `adapter/parser.go` |
| BasicOption | `adapter/outbound/base.go` | `adapter/outbound/base.go` |
| VMess | `adapter/outbound/vmess.go` | `adapter/outbound/vmess.go` |
| VLESS | `adapter/outbound/vless.go` | — (quirktiva uses different struct) |
| Trojan | `adapter/outbound/trojan.go` | `adapter/outbound/trojan.go` |
| Shadowsocks | `adapter/outbound/shadowsocks.go` | `adapter/outbound/shadowsocks.go` |
| ShadowsocksR | `adapter/outbound/shadowsocksr.go` | `adapter/outbound/shadowsocksr.go` |
| SOCKS5 | `adapter/outbound/socks5.go` | `adapter/outbound/socks5.go` |
| HTTP | `adapter/outbound/http.go` | `adapter/outbound/http.go` |
| TUIC | `adapter/outbound/tuic.go` | — |
| Hysteria2 | `adapter/outbound/hysteria2.go` | `adapter/outbound/hysteria2.go` |
| Hysteria1 | `adapter/outbound/hysteria.go` | — |
| WireGuard | `adapter/outbound/wireguard.go` | `adapter/outbound/wireguard.go` |
| Snell | `adapter/outbound/snell.go` | `adapter/outbound/snell.go` |
| AnyTLS | `adapter/outbound/anytls.go` | `adapter/outbound/anytls.go` |
| SSH | `adapter/outbound/ssh.go` | — |
| Tailscale | `adapter/outbound/tailscale.go` | — |
| Proxy groups | `adapter/outboundgroup/groupbase.go` | `adapter/outboundgroup/` |
| Providers | `adapter/provider/parser.go` | `adapter/provider/` |
| Rules | `rules/parser.go` | `rules/` |
| Rule providers | `rules/provider/parse.go` | `rules/provider/` |
| DNS config | `config/config.go` RawDNS | `config/config.go` |
| TUN config | `config/config.go` RawTun | `config/config.go` |
| Sniffer | `config/config.go` RawSniffer | — |
| Profile cache | `component/profile/cachefile/cache.go` | — |

### AdapterType Constants (mihomo `constant/adapters.go`)

```
Direct, Reject, RejectDrop, Pass, Compatible,
Rematch, TcpAdapter,
Shadowsocks, ShadowsocksR,
Snell,
Socks5, Http,
Vmess, Vless, Trojan,
Hysteria, Hysteria2,
WireGuard, Tuic,
GostRelay,
AnyTLS, Ssh,
Tailscale,
Mieru, Sudoku,
Masque, TrustTunnel,
OpenVPN,
Selector, Fallback, URLTest, LoadBalance, Relay
```

---

*Last updated: 2026-07-08*
