# thirdparty/ reference index

Read-only reference material for **leas**. Nothing here is built, linked, or
shipped. Source of truth for pins is [`thirdparty.toml`](../thirdparty.toml)
at the repo root: every tag / exact revision plus its resolved sha, committed
so `git log -p -- thirdparty.toml` is the full history of referencing.

Regenerate both files from disk: `python3 refresh.py --sync`.
Drift check (read-only, default): `python3 refresh.py`. Upstream existence:
`python3 refresh.py --probe`. Reconcile drift: `python3 refresh.py --apply`
(never touches frozen entries).

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

## Entries

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
- To change a pin: edit `thirdparty.toml` (or re-clone then `--sync`) and
  commit it. The commit message is the 'why' behind the reference change.
- Adding a repo: clone it under `thirdparty/`, run `--sync`, commit the diff.
- Removing a repo: delete its folder, run `--sync`, commit. Never `rm` inside
  a frozen folder.
