# thirdparty/ reference index

Read-only reference material for **leas**. Nothing here is built, linked, or
shipped. Source of truth for pins is [`thirdparty.toml`](../thirdparty.toml)
at the repo root: every tag / exact revision plus its resolved sha, committed
so `git log -p -- thirdparty.toml` is the full history of referencing.

## Commands

| command | effect |
| --- | --- |
| `python3 refresh.py` | default; read-only drift report (no clone/fetch/delete) |
| `python3 refresh.py --probe` | + upstream existence via GitHub API (`UV_GITHUB_TOKEN`) |
| `python3 refresh.py --sync` | rebuild manifest AND index **from disk** — overwrites hand edits |
| `python3 refresh.py --index` | regenerate only this INDEX **from the manifest** (safe after a hand edit) |
| `python3 refresh.py --apply` | reconcile non-frozen drifts to pinned sha (destructive; never touches frozen) |

`.gitignore` ignores `thirdparty/**` but whitelists `*.md`, so this INDEX is
tracked and the repo contents are not.

## Status legend

| status | meaning |
| --- | --- |
| `reference` | normal upstream-tracked git repo, pinned to a branch HEAD sha |
| `pinned-tag` | pinned to an exact release tag |
| `ad-hoc-research` | local work or origin drift; kept frozen, never refreshed |
| `frozen` | non-git local snapshot; no upstream, never refreshed |
| `gone` | upstream vanished (GitHub 404); only frozen copy |
| `private-host` | private/internal git host, not probeable via public API |

Frozen, gone, private-host and ad-hoc-research entries are **never** modified
by `--apply`. Treat them as archival.

## What each folder is (purpose · domain · tags · standards)

Each tag is a search hint: scan the `#hashtags` column to jump to the right
folder for a protocol, transport, RFC, or tech domain. Details live in the
committed manifest (`what` / `domain` / `tags` / `standards` per entry).

| folder | what it is | domain | tags | protocols / RFCs / transports |
| --- | --- | --- | --- | --- |
| `anytls-go` | AnyTLS proxy protocol reference implementation (Go) | proxy protocol | #anytls #tls-in-tls #go #reference | AnyTLS; TLS-in-TLS fingerprint mitigation; connection reuse |
| `anytls-rs` | High-performance AnyTLS proxy in Rust, sing-box interop | proxy server | #anytls #rust #observability #socks5 | AnyTLS; SOCKS5; HTTP CONNECT; TLS cert hot reload; sing-box outbound |
| `async-socks5` | Async SOCKS5/4/4a client, Tokio, no unsafe | SOCKS client | #socks5 #rust #tokio #client | SOCKS5 (RFC 1928); SOCKS4/4a |
| `Bushuray-tui` | Keyboard-driven Xray TUI (Go, bubbletea) | desktop TUI client | #tui #xray #go #bubbletea | Xray client; terminal UI |
| `craftls` | rustls fork with customizable ClientHello fingerprint | TLS library | #tls #rustls #rust #fingerprint | TLS 1.3; ClientHello customization |
| `curl-impersonate` | curl fork impersonating Chrome/Edge/Safari/Firefox | HTTP/TLS client | #curl #tls #http2 #browser-fingerprint | TLS ClientHello; HTTP/2 SETTINGS + HPACK; browser profiles |
| `CycleTLS` | High-performance HTTP client with TLS fingerprint (Go) | HTTP client | #http-client #ja3 #go #fingerprint | JA3/JA4 TLS fingerprint impersonation; goroutine pool |
| `dnscrypt` | DNSCrypt v2 implementation in Go (AdGuard) | encrypted DNS | #dns #dnscrypt #go #library | DNSCrypt v2; encrypted DNS |
| `DNSveil` | Secure DNS client for Windows | desktop DNS client | #dns #dnscrypt #doh #dot #windows | DNSCrypt; Anonymized DNSCrypt; DoH (RFC 8484); DoT (RFC 7858); plain DNS |
| `encrypted-dns-server` | High-performance encrypted DNS proxy server (Rust) | DNS server | #dns #dnscrypt #rust #server | DNSCrypt v2; post-quantum DNSCrypt (PQDNSCrypt); DoH; DoT |
| `fast-socks5` | Async SOCKS5/4/4a Tokio client, no unsafe | SOCKS client | #socks5 #rust #tokio #client | SOCKS5 (RFC 1928); SOCKS4/4a; UDP ASSOCIATE |
| `ferrox` | From-scratch proxy core targeting bit-identical parity | proxy core | #proxy-core #rust #parity #tls | TLS engine; proxy wire parity; protocol transports |
| `geektls` | Multilingual TLS/HTTP full-stack fingerprint forge | fingerprint library | #tls #http2 #http3 #quic #ja3 #ja4 | JA3/JA4; HTTP/2 Akamai fingerprint + HPACK; HTTP/3 + QUIC; TCP-layer fingerprint; Python/Node/Go APIs |
| `go-shadowsocks2` | Shadowsocks implementation in Go | proxy server | #shadowsocks #go #proxy | Shadowsocks; SOCKS5 UDP Associate; Linux netfilter TCP redirect |
| `goida-vpn-configs` | Auto-updated public VPN config collection (GitLab) | subscription feed | #subscriptions #vpn-configs #gitlab | V2Ray/VLESS/Hysteria/Trojan/VMess/REALITY/Shadowsocks share links |
| `hashify` | Compile-time perfect hash macro crate (Rust) | compiler macro | #macro #hash #rust #no-alloc | Perfect hash lookups; no runtime deps; no unsafe |
| `hysteria` | Hysteria 2 QUIC-based proxy (Go) | proxy server | #hysteria2 #quic #go #proxy | Hysteria 2; QUIC; congestion control (Brutal) |
| `hysteria-legacy-v1` | Hysteria v1 (hy1 branch), QUIC proxy | proxy server | #hysteria #quic #go #legacy | Hysteria v1; QUIC |
| `impersonator` | BouncyCastle-bctls + okhttp fork for TLS/JA3 impersonation | HTTP/TLS client | #tls #ja3 #http2 #java #fingerprint | TLS/JA3 fingerprint; HTTP/2 fingerprint; Java/okhttp |
| `impit` | Browser-impersonating HTTP client library (Rust) | HTTP client | #http-client #fingerprint #rust | HTTP/1.1; HTTP/2; HTTP/3; reqwest + rustls + tokio |
| `ja4db-export` | JA4DB export tooling (Python; public API defunct) | fingerprint data tool | #ja4 #python #fingerprint | JA4 fingerprint database export (API no longer reachable) |
| `jets` | Rule-based tunnel in Rust | tunnel | #tunnel #rust #rules | Rule-based routing; secure network access |
| `leaf` | Versatile proxy framework in Rust | proxy framework | #proxy-framework #rust #multi-protocol | Multiple proxy protocols; transports & security; transparent proxy; traffic control |
| `leaktracer` | Rust allocator tracing memory allocations | memory tooling | #allocator #memory #rust #tracing | GlobalAlloc; allocation tracing; heap stats |
| `matryoshka` | Terminal UI proxy manager for Xray (Python/Textual) | desktop TUI client | #tui #proxy-manager #python #textual | Gateway chaining; latency testing; subscription fetching; Xray configs |
| `microrm` | No-DSL ORM for SQLite in Rust | database | #orm #sqlite #rust #macro | SQLite; proc-macro schema from Rust types; sync + async |
| `mihomo` | Clash Meta (Mihomo) universal proxy platform (Go) | proxy core | #mihomo #clash #go #proxy-core | VMess/VLESS/SS/Trojan/Snell/TUIC/Hysteria; Clash YAML; DoH/DoT; fake-ip DNS |
| `outbound` | Dialer library built from share links (daeuniverse, Go) | dialer library | #dialer #share-link #go | Share-link parsing; dialer construction; VMess/VLESS/SS/Trojan |
| `purecrypto` | Pure-Rust cryptography toolkit, no foreign code | cryptography | #crypto #rust #post-quantum #no-unsafe | Constant-time primitives; hashing; ciphers; bignum; classical + post-quantum asymmetric |
| `quic-go-v0.20.1` | Pure-Go QUIC implementation pinned at v0.20.1 | QUIC library | #quic #go #pinned | QUIC IETF draft-29/32/34 |
| `quirktiva` | Mihomo fork (plus branch) with extra protocols | proxy core | #quirktiva #clash-fork #go | SS/VMess/VLESS/Trojan/WireGuard/Hysteria2; fake-ip DNS; SOCKS5/HTTP outbound |
| `ratatui-cheese` | Bubbletea-inspired components for Ratatui | TUI widgets | #ratatui #tui #widgets #rust | TUI widget library (spinner, animation, inputs) |
| `ratatui-themes` | Color themes for Ratatui apps | TUI themes | #ratatui #themes #tui #rust | 15+ themes (Dracula, Nord, Catppuccin, Gruvbox) |
| `REALITY` | Server side of XTLS REALITY protocol (Go tls fork) | TLS server | #reality #xtls #tls #go #server | REALITY protocol; TLS 1.3 |
| `roscomvpn-geoip` | Generates geoip.dat + rulesets with RU/BY CIDR filtering | routing data | #geoip #routing #russia #dat | geoip.dat; CIDR routing (direct/whitelist/private) |
| `roscomvpn-geosite` | Generates geosite.dat + domain category lists | routing data | #geosite #routing #russia #dat | geosite.dat; domain-category routing |
| `roscomvpn-routing` | Ready routing configs for Happ/INCY/Mihomo | routing configs | #routing #clash #mihomo #russia | Clash/Mihomo routing rulesets |
| `russia-mobile-internet-whitelist` | RU mobile operator CIDR/domain allowlists | routing data | #whitelist #russia #cidr #geo | CIDR allowlists; domain allowlists |
| `shadowsocks-rust` | Shadowsocks port in Rust | proxy server | #shadowsocks #rust #proxy | Shadowsocks; AEAD ciphers; SIP002/2022 |
| `shoes` | High-performance multi-protocol proxy server (Rust) | proxy server | #proxy #rust #server #multi-protocol | Multi-protocol proxy; CLI/config examples |
| `sing-box` | Universal proxy platform (SagerNet, Go) | proxy core | #singbox #proxy-core #go | VMess/VLESS/Trojan/SS/Hysteria/TUIC/Snell/WireGuard; TCP/WS/HTTP/gRPC/QUIC; DoH/DoT/fake-ip DNS |
| `sing-mux` | Simple stream multiplex library (Go) | multiplexing | #mux #multiplex #go #singbox | Stream multiplexing; session management |
| `smux` | Stream multiplexer for Go (sing-box mod) | multiplexing | #mux #multiplex #go | Stream-oriented multiplexing over TCP/UDS |
| `sniffnet` | Network traffic monitor (Rust) | network monitoring | #network-monitor #rust #tui | Packet capture; traffic stats; cross-platform |
| `soar` | DNS tunnel for censored networks (Getlantern, Go) | DNS tunnel | #dns-tunnel #censorship #go #quic | DNS tunneling; QUIC; L1 obfuscation |
| `starrocks` | Launcher/manager for StarRocks nodes (private internal) | internal tooling | #starrocks #internal #launcher | StarRocks node management (private GitLab) |
| `StormDNS` | TCP-over-DNS tunnel with local SOCKS5 (Go) | DNS tunnel | #dns-tunnel #tcp #socks5 #go | DNS query/response tunneling; SOCKS5; raw TCP listener |
| `sub-healer` | Local subscription-healing research (Rust) | local research | #subscription #local-research #rust | Subscription repair (local-only HEAD; not upstream) |
| `subconverter` | Proxy subscription format converter (C++) | subscription tool | #subscriptions #converter #cpp | Multiple subscription formats; Clash/Surge/V2Ray output |
| `tls-fingerprint` | Rust TLS ClientHello/fingerprint crate (frozen source) | TLS library | #tls #fingerprint #rust #leas-source | ClientHello construction; TLS 1.3 secrets; HTTP/2 fingerprint; ported into leas-tls |
| `toasty` | Embedded database for Rust (tokio-rs) | database | #database #rust #embedded | Embedded SQL storage; derive APIs |
| `tracing_allocator` | Rust global allocator logging allocations to file | memory tooling | #allocator #memory #rust #tracing | GlobalAlloc; allocation logging |
| `trojan` | Trojan proxy over TLS (C++) | proxy server | #trojan #tls #cpp #proxy | Trojan protocol over TLS; unidentifiable proxy |
| `TrojanRust` | High-performance Trojan proxy in Rust (tokio) | proxy server | #trojan #rust #tokio #proxy | Trojan protocol; TLS; performance focus |
| `tui-widgets` | Widget collection for Ratatui | TUI widgets | #ratatui #widgets #tui #rust | Scrollview, QR code, scrollbar, popup, prompts, charts |
| `tuic` | QUIC-based low-latency proxy (Rust fork) | proxy server | #tuic #quic #rust #proxy | TUIC protocol; QUIC; low handshake overhead; routing/observability |
| `turso` | In-process SQLite-compatible database (Rust) | database | #database #sqlite #rust #turso | SQLite file format; SQL; Postgres wire frontend |
| `unbihex` | Russian VPN client on own Rust core, Xray-compatible | desktop VPN client | #vpn-client #rust #xray-compatible | VLESS (TLS/REALITY/Vision/XHTTP/WS/HTTPUpgrade/gRPC); VMess (TCP/TLS/WS/HTTPUpgrade) |
| `utls` | uTLS fork of Go crypto/tls with ClientHello fingerprinting | TLS library | #tls #ja3 #ja4 #fingerprint #go #clienthello | TLS 1.2/1.3; ClientHello fingerprint resistance; fake session tickets; ECH; BoringSSL padding |
| `v2ray-configs` | Bulk V2Ray configs (GONE - upstream 404, frozen) | subscription feed | #vpn-configs #gone #frozen | V2Ray config collection |
| `v2ray-core` | V2Fly core (Go) | proxy core | #v2ray #vmess #go #proxy-core | VMess; VLESS; SOCKS/HTTP inbound; TCP/WS/gRPC transports |
| `v2ray-core-legacy` | Original v2ray/v2ray-core, moved to v2fly | proxy core (legacy) | #v2ray #legacy #go | VMess; legacy V2Ray protocol suite |
| `v2ray-core-v4.38.3` | V2Fly core pinned at v4.38.3 | proxy core (pinned) | #v2ray #pinned-old #go | VMess/VLESS; legacy transports |
| `v2ray-plugin` | SIP003 Shadowsocks plugin based on v2ray (Go) | proxy plugin | #sip003 #shadowsocks #plugin #go | SIP003 plugin; WebSocket/QUIC plugin modes |
| `v2rayN` | GUI client for Windows/Linux/macOS (C#) | desktop GUI client | #desktop-gui #csharp #client | Xray and sing-box cores; SOCKS/HTTP inbound |
| `v2rayNG` | Android V2Ray client (Kotlin) | mobile VPN client | #android #mobile-client | Xray/v2fly cores; VLESS/VMess/Trojan/SS |
| `vpn-configs-for-russia` | Free VPN configs working in RU | subscription feed | #vpn-configs #russia | VLESS/VMess configs; subscription lists |
| `wireguard-go` | WireGuard implementation in Go | VPN | #wireguard #vpn #go | WireGuard protocol; Noise framework; UDP |
| `wreq-util` | Utilities for the wreq HTTP client (Rust) | HTTP client utils | #http-client #rust #wreq | HTTP client helpers; browser-impersonation adjacent |
| `xrat` | Terminal CLI/TUI/Web UI proxy tester + subscription manager (Rust) | proxy manager | #tui #cli #proxy-tester #rust | Subscription import; proxy testing; saved results |
| `xray-checker` | Proxy availability monitoring with Prometheus (Go) | monitoring | #monitoring #xray #prometheus #go | VLESS/VMess/Trojan/SS probing; Prometheus metrics |
| `xray-config-toolkit` | Xray config builder / Iranian-site bypass | config tool | #config-tool #xray #iran | Xray configs; subscription links; bypass rulesets |
| `Xray-core` | XTLS Xray-core network tools (Go) | proxy core | #xray #xtls #go #proxy-core | VLESS; VMess; Trojan; SS; REALITY; XTLS Vision; XHTTP; TCP/WS/gRPC/QUIC |
| `xray-rs-tls` | Rust TLS/obfuscation experiment (frozen source) | TLS experiment | #tls #rust #xray #obfuscation | Referenced by leas-native salamander.rs |
| `yamux` | Yet Another Multiplexer for Go | multiplexing | #yamux #mux #go | Stream-oriented multiplexing over TCP/UDS |
| `zellij` | Terminal workspace / multiplexer (Rust) | terminal multiplexer | #terminal #multiplexer #rust #tui | Panes/tabs; terminal multiplexing (local edits) |
| `ZeroNet` | Persian VPN client on Rust 'Zray' core | VPN client | #vpn-client #rust #persian | VPN protocols; Zray core (local edits) |

## Pins (exact tag / revision per entry)

Total: 77 (gone: 1, frozen: 2, private-host: 1, ad-hoc-research: 3, pinned-tag: 22, reference: 48)

| folder | kind | status | host | ref | sha |
| --- | --- | --- | --- | --- | --- |
| `anytls-go` | git | reference | github | `main@fd6167acd6d7` | `fd6167acd6d7` |
| `anytls-rs` | git | reference | github | `main@f09613e0102d` | `f09613e0102d` |
| `async-socks5` | git | reference | github | `master@a6f55c11742c` | `a6f55c11742c` |
| `Bushuray-tui` | git | pinned-tag | github | `v0.2.3` | `b89fe5514328` |
| `craftls` | git | reference | github | `craft-0.22.0@4d1da98768af` | `4d1da98768af` |
| `curl-impersonate` | git | reference | github | `main@ec2a2317f14f` | `ec2a2317f14f` |
| `CycleTLS` | git | reference | github | `main@9671e0488491` | `9671e0488491` |
| `dnscrypt` | git | reference | github | `master@4822c9b2045b` | `4822c9b2045b` |
| `DNSveil` | git | reference | github | `main@42ac542d081c` | `42ac542d081c` |
| `encrypted-dns-server` | git | reference | github | `master@2f2cc489ff88` | `2f2cc489ff88` |
| `fast-socks5` | git | reference | github | `master@bae2fc05f993` | `bae2fc05f993` |
| `ferrox` | git | reference | github | `main@0ec73b107891` | `0ec73b107891` |
| `geektls` | git | reference | github | `bindings/golang/v0.2.2` | `3b64bcf0b0a1` |
| `go-shadowsocks2` | git | reference | github | `master@e1fe9ea73740` | `e1fe9ea73740` |
| `goida-vpn-configs` | git | reference | gitlab | `main@c8858d9a19eb` | `c8858d9a19eb` |
| `hashify` | git | pinned-tag | github | `v0.3.2` | `b6f1ab99609d` |
| `hysteria` | git | reference | github | `master@747a11182458` | `747a11182458` |
| `hysteria-legacy-v1` | git | reference | github | `hy1@ac56271d0303` | `ac56271d0303` |
| `impersonator` | git | reference | github | `master@789ecd2bf522` | `789ecd2bf522` |
| `impit` | git | reference | github | `master@4fd6c3167c55` | `4fd6c3167c55` |
| `ja4db-export` | git | reference | github | `main@af1618e515f8` | `af1618e515f8` |
| `jets` | git | pinned-tag | github | `v0.4.3` | `a144f3073e35` |
| `leaf` | git | reference | github | `master@5e8d94759ce9` | `5e8d94759ce9` |
| `leaktracer` | git | reference | github | `main@28cf14b1dc5c` | `28cf14b1dc5c` |
| `matryoshka` | git | pinned-tag | github | `2026-09-07-153737` | `7dc16e9fef38` |
| `microrm` | git | reference | codeberg | `main@5c4052363003` | `5c4052363003` |
| `mihomo` | git | pinned-tag | github | `v1.19.33` | `3f27ef39f8c9` |
| `outbound` | git | reference | github | `main@cfd9e39fd5e0` | `cfd9e39fd5e0` |
| `purecrypto` | git | pinned-tag | github | `v0.10.6` | `c90ae979e968` |
| `quic-go-v0.20.1` | git | pinned-tag | github | `v0.20.1` | `40b124d209d1` |
| `quirktiva` | git | pinned-tag | github | `v1.91.0` | `1eac02b730b5` |
| `ratatui-cheese` | git | pinned-tag | github | `v0.7.0` | `ef8464bd6a59` |
| `ratatui-themes` | git | reference | github | `main@909fa2b2ee13` | `909fa2b2ee13` |
| `REALITY` | git | reference | github | `main@4a26e87788f5` | `4a26e87788f5` |
| `roscomvpn-geoip` | git | pinned-tag | github | `202611101104` | `8f0e50bad620` |
| `roscomvpn-geosite` | git | reference | github | `master@300324058785` | `300324058785` |
| `roscomvpn-routing` | git | reference | github | `main@fcc084734ab4` | `fcc084734ab4` |
| `russia-mobile-internet-whitelist` | git | reference | github | `main@fad3653ebd4b` | `fad3653ebd4b` |
| `shadowsocks-rust` | git | reference | github | `master@e697eb292b66` | `e697eb292b66` |
| `shoes` | git | pinned-tag | github | `v0.3.7` | `ee44a397e685` |
| `sing-box` | git | pinned-tag | github | `v1.15.0-alpha.13` | `824dbcfb4dd0` |
| `sing-mux` | git | reference | github | `HEAD@caf09fe32475` | `caf09fe32475` |
| `smux` | git | pinned-tag | github | `v1.5.50-sing-box-mod.1` | `f373f1e706bf` |
| `sniffnet` | git | reference | github | `main@a4655590f6fe` | `a4655590f6fe` |
| `soar` | git | pinned-tag | github | `v0.2.4` | `fea80aae6c60` |
| `starrocks` | git | private-host | private | `master@4d515dd4dd05` | `4d515dd4dd05` |
| `StormDNS` | git | reference | github | `main@a9a8e92a51f0` | `a9a8e92a51f0` |
| `sub-healer` | git | ad-hoc-research | github | `master@26e5f0631a5f` | `26e5f0631a5f` |
| `subconverter` | git | reference | github | `master@a0d4eab28cb8` | `a0d4eab28cb8` |
| `tls-fingerprint` | artifact | frozen | local | `-` | `-` |
| `toasty` | git | reference | github | `main@4f3ed1a351f9` | `4f3ed1a351f9` |
| `tracing_allocator` | git | reference | github | `master@dc29ba70ae5a` | `dc29ba70ae5a` |
| `trojan` | git | reference | github | `master@3e7bb9aecdc6` | `3e7bb9aecdc6` |
| `TrojanRust` | git | reference | github | `main@06a32afcf759` | `06a32afcf759` |
| `tui-widgets` | git | reference | github | `main@dec872b2cb87` | `dec872b2cb87` |
| `tuic` | git | reference | github | `main@27e666ceee7d` | `27e666ceee7d` |
| `turso` | git | pinned-tag | github | `v0.9.0-pre.5` | `98dc77b9f793` |
| `unbihex` | git | pinned-tag | github | `v0.2.10` | `dd4ca980d6dc` |
| `utls` | git | reference | github | `master@360383f893fb` | `360383f893fb` |
| `v2ray-configs` | git | gone | github | `main@333276ba1ca0` | `333276ba1ca0` |
| `v2ray-core` | git | reference | github | `master@ec5ce8ba78e8` | `ec5ce8ba78e8` |
| `v2ray-core-legacy` | git | reference | github | `master@d80440f3d57b` | `d80440f3d57b` |
| `v2ray-core-v4.38.3` | git | pinned-tag | github | `v4.38.3` | `ffc8887d79bc` |
| `v2ray-plugin` | git | pinned-tag | github | `v1.3.2` | `ddd7ab46b4ae` |
| `v2rayN` | git | reference | github | `master@f07e3dc41511` | `f07e3dc41511` |
| `v2rayNG` | git | reference | github | `master@9397a9e4a17e` | `9397a9e4a17e` |
| `vpn-configs-for-russia` | git | reference | github | `main@229b9b04ef8f` | `229b9b04ef8f` |
| `wireguard-go` | git | reference | github | `master@b3bc704ef0ee` | `b3bc704ef0ee` |
| `wreq-util` | git | reference | github | `main@917d2581d676` | `917d2581d676` |
| `xrat` | git | pinned-tag | github | `v0.35.1` | `055265c5cc06` |
| `xray-checker` | git | pinned-tag | github | `v1.3.1` | `f829c2b7d446` |
| `xray-config-toolkit` | git | reference | github | `main@bbbd28ae0b55` | `bbbd28ae0b55` |
| `Xray-core` | git | pinned-tag | github | `v26.11.9` | `676eaf66f8f0` |
| `xray-rs-tls` | artifact | frozen | local | `-` | `-` |
| `yamux` | git | pinned-tag | github | `v0.1.2` | `17017e907efc` |
| `zellij` | git | ad-hoc-research | github | `main@9e7be20f5c15` | `9e7be20f5c15` |
| `ZeroNet` | git | ad-hoc-research | github | `v0.3.6` | `29e7a95eaaf7` |

## Frozen / archival detail

- **`starrocks`** (private-host) — Private/internal host; not probeable via public API.
- **`sub-healer`** (ad-hoc-research) — HEAD commit is not on upstream (local/rewritten); local edits present.
- **`tls-fingerprint`** (frozen) — Rust crate source; ported into leas-tls (crypto/handshake/hello/http2/record).
- **`v2ray-configs`** (gone) — Upstream GitHub repo returns 404; this is the only frozen copy.
- **`xray-rs-tls`** (frozen) — Rust crate source; referenced by leas-native/src/crypto/salamander.rs.
- **`zellij`** (ad-hoc-research) — Uncommitted local changes; pinned sha is the committed HEAD.
- **`ZeroNet`** (ad-hoc-research) — Uncommitted local changes; pinned sha is the committed HEAD.

## Conventions

- One top-level folder per repo. Shallow clones (`--depth 1`) are the norm;
  `shallow` is recorded in the manifest.
- Change a pin: edit `thirdparty.toml`, then `python3 refresh.py --index`
  (do NOT run `--sync` — it rebuilds the manifest from disk and loses edits).
  Commit with a message that says why the revision changed.
- Add a repo: clone under `thirdparty/`, run `--sync`, commit both files.
- Remove a repo: delete its folder, run `--sync`, commit. Never `rm` inside
  a frozen folder.
- `tls-engine/` was flattened: its 4 repos are now top-level `geektls`,
  `purecrypto`, `curl-impersonate`, `utls` (the last two replaced older copies;
  superseded SHAs are in the manifest `notes`). Research docs that still cite
  `thirdparty/tls-engine/*` are historical — resolve them via this INDEX.
