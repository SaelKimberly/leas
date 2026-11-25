"""Inventory and stabilize ``thirdparty/``.

The committed ``thirdparty.toml`` is the single source of truth. Every pin
(tag or exact revision) plus its resolved 40-char sha lives there, so
``git log -p -- thirdparty.toml`` is the whole history of referencing.

Default run is a read-only drift report. No clone, no fetch, no delete.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess as sp
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import final

ROOT = Path(__file__).resolve().parent
THIRDPARTY = ROOT / "thirdparty"
MANIFEST = ROOT / "thirdparty.toml"
INDEX = THIRDPARTY / "INDEX.md"

# Non-git entries that are kept as frozen local snapshots (no upstream).
FROZEN_ARTIFACTS: dict[str, str] = {
    "tls-fingerprint": "Rust crate source; ported into leas-tls (crypto/handshake/hello/http2/record).",
    "xray-rs-tls": "Rust crate source; referenced by leas-native/src/crypto/salamander.rs.",
}

# Folders whose upstream vanished or whose history is intentionally pinned.
# Never refreshed by --apply; still reconciled and reported.
GONE = {"v2ray-configs"}                 # github.com/Epodonios/v2ray-configs -> 404
PRIVATE_HOSTS = {"starrocks"}            # private GitLab, not probeable
LOCAL_WORK = {"sub-healer"}              # HEAD not upstream; local edits present

# Flattening tls-engine/ replaced these top-level copies with newer revisions.
# Kept as provenance so the swap is auditable in git history.
SUPERSEDED: dict[str, str] = {
    "curl-impersonate": "replaced v2.1.1 / 86e5f1f822566827cc413de843acdac60057a37c (2026-08-20)",
    "utls": "replaced a13c59ffe98bb01b2ca14143eb2e887664b1f138 (2026-11-08)",
}

# Curated reference data: "what it is | tech domain | hashtags | protocols/RFCs/transports".
# Kept in the generator so `--sync` regenerates INDEX.md without losing it.
CURATION: dict[str, str] = {
    "anytls-go": "AnyTLS proxy protocol reference implementation (Go) | proxy protocol | #anytls #tls-in-tls #go #reference | AnyTLS; TLS-in-TLS fingerprint mitigation; connection reuse",
    "anytls-rs": "High-performance AnyTLS proxy in Rust, sing-box interop | proxy server | #anytls #rust #observability #socks5 | AnyTLS; SOCKS5; HTTP CONNECT; TLS cert hot reload; sing-box outbound",
    "async-socks5": "Async SOCKS5/4/4a client, Tokio, no unsafe | SOCKS client | #socks5 #rust #tokio #client | SOCKS5 (RFC 1928); SOCKS4/4a",
    "Bushuray-tui": "Keyboard-driven Xray TUI (Go, bubbletea) | desktop TUI client | #tui #xray #go #bubbletea | Xray client; terminal UI",
    "craftls": "rustls fork with customizable ClientHello fingerprint | TLS library | #tls #rustls #rust #fingerprint | TLS 1.3; ClientHello customization",
    "curl-impersonate": "curl fork impersonating Chrome/Edge/Safari/Firefox | HTTP/TLS client | #curl #tls #http2 #browser-fingerprint | TLS ClientHello; HTTP/2 SETTINGS + HPACK; browser profiles",
    "CycleTLS": "High-performance HTTP client with TLS fingerprint (Go) | HTTP client | #http-client #ja3 #go #fingerprint | JA3/JA4 TLS fingerprint impersonation; goroutine pool",
    "dnscrypt": "DNSCrypt v2 implementation in Go (AdGuard) | encrypted DNS | #dns #dnscrypt #go #library | DNSCrypt v2; encrypted DNS",
    "DNSveil": "Secure DNS client for Windows | desktop DNS client | #dns #dnscrypt #doh #dot #windows | DNSCrypt; Anonymized DNSCrypt; DoH (RFC 8484); DoT (RFC 7858); plain DNS",
    "encrypted-dns-server": "High-performance encrypted DNS proxy server (Rust) | DNS server | #dns #dnscrypt #rust #server | DNSCrypt v2; post-quantum DNSCrypt (PQDNSCrypt); DoH; DoT",
    "fast-socks5": "Async SOCKS5/4/4a Tokio client, no unsafe | SOCKS client | #socks5 #rust #tokio #client | SOCKS5 (RFC 1928); SOCKS4/4a; UDP ASSOCIATE",
    "ferrox": "From-scratch proxy core targeting bit-identical parity | proxy core | #proxy-core #rust #parity #tls | TLS engine; proxy wire parity; protocol transports",
    "geektls": "Multilingual TLS/HTTP full-stack fingerprint forge | fingerprint library | #tls #http2 #http3 #quic #ja3 #ja4 | JA3/JA4; HTTP/2 Akamai fingerprint + HPACK; HTTP/3 + QUIC; TCP-layer fingerprint; Python/Node/Go APIs",
    "go-shadowsocks2": "Shadowsocks implementation in Go | proxy server | #shadowsocks #go #proxy | Shadowsocks; SOCKS5 UDP Associate; Linux netfilter TCP redirect",
    "goida-vpn-configs": "Auto-updated public VPN config collection (GitLab) | subscription feed | #subscriptions #vpn-configs #gitlab | V2Ray/VLESS/Hysteria/Trojan/VMess/REALITY/Shadowsocks share links",
    "hashify": "Compile-time perfect hash macro crate (Rust) | compiler macro | #macro #hash #rust #no-alloc | Perfect hash lookups; no runtime deps; no unsafe",
    "hysteria": "Hysteria 2 QUIC-based proxy (Go) | proxy server | #hysteria2 #quic #go #proxy | Hysteria 2; QUIC; congestion control (Brutal)",
    "hysteria-legacy-v1": "Hysteria v1 (hy1 branch), QUIC proxy | proxy server | #hysteria #quic #go #legacy | Hysteria v1; QUIC",
    "impersonator": "BouncyCastle-bctls + okhttp fork for TLS/JA3 impersonation | HTTP/TLS client | #tls #ja3 #http2 #java #fingerprint | TLS/JA3 fingerprint; HTTP/2 fingerprint; Java/okhttp",
    "impit": "Browser-impersonating HTTP client library (Rust) | HTTP client | #http-client #fingerprint #rust | HTTP/1.1; HTTP/2; HTTP/3; reqwest + rustls + tokio",
    "ja4db-export": "JA4DB export tooling (Python; public API defunct) | fingerprint data tool | #ja4 #python #fingerprint | JA4 fingerprint database export (API no longer reachable)",
    "jets": "Rule-based tunnel in Rust | tunnel | #tunnel #rust #rules | Rule-based routing; secure network access",
    "leaf": "Versatile proxy framework in Rust | proxy framework | #proxy-framework #rust #multi-protocol | Multiple proxy protocols; transports & security; transparent proxy; traffic control",
    "leaktracer": "Rust allocator tracing memory allocations | memory tooling | #allocator #memory #rust #tracing | GlobalAlloc; allocation tracing; heap stats",
    "matryoshka": "Terminal UI proxy manager for Xray (Python/Textual) | desktop TUI client | #tui #proxy-manager #python #textual | Gateway chaining; latency testing; subscription fetching; Xray configs",
    "microrm": "No-DSL ORM for SQLite in Rust | database | #orm #sqlite #rust #macro | SQLite; proc-macro schema from Rust types; sync + async",
    "mihomo": "Clash Meta (Mihomo) universal proxy platform (Go) | proxy core | #mihomo #clash #go #proxy-core | VMess/VLESS/SS/Trojan/Snell/TUIC/Hysteria; Clash YAML; DoH/DoT; fake-ip DNS",
    "outbound": "Dialer library built from share links (daeuniverse, Go) | dialer library | #dialer #share-link #go | Share-link parsing; dialer construction; VMess/VLESS/SS/Trojan",
    "purecrypto": "Pure-Rust cryptography toolkit, no foreign code | cryptography | #crypto #rust #post-quantum #no-unsafe | Constant-time primitives; hashing; ciphers; bignum; classical + post-quantum asymmetric",
    "quic-go-v0.20.1": "Pure-Go QUIC implementation pinned at v0.20.1 | QUIC library | #quic #go #pinned | QUIC IETF draft-29/32/34",
    "quirktiva": "Mihomo fork (plus branch) with extra protocols | proxy core | #quirktiva #clash-fork #go | SS/VMess/VLESS/Trojan/WireGuard/Hysteria2; fake-ip DNS; SOCKS5/HTTP outbound",
    "ratatui-cheese": "Bubbletea-inspired components for Ratatui | TUI widgets | #ratatui #tui #widgets #rust | TUI widget library (spinner, animation, inputs)",
    "ratatui-themes": "Color themes for Ratatui apps | TUI themes | #ratatui #themes #tui #rust | 15+ themes (Dracula, Nord, Catppuccin, Gruvbox)",
    "REALITY": "Server side of XTLS REALITY protocol (Go tls fork) | TLS server | #reality #xtls #tls #go #server | REALITY protocol; TLS 1.3",
    "roscomvpn-geoip": "Generates geoip.dat + rulesets with RU/BY CIDR filtering | routing data | #geoip #routing #russia #dat | geoip.dat; CIDR routing (direct/whitelist/private)",
    "roscomvpn-geosite": "Generates geosite.dat + domain category lists | routing data | #geosite #routing #russia #dat | geosite.dat; domain-category routing",
    "roscomvpn-routing": "Ready routing configs for Happ/INCY/Mihomo | routing configs | #routing #clash #mihomo #russia | Clash/Mihomo routing rulesets",
    "russia-mobile-internet-whitelist": "RU mobile operator CIDR/domain allowlists | routing data | #whitelist #russia #cidr #geo | CIDR allowlists; domain allowlists",
    "shadowsocks-rust": "Shadowsocks port in Rust | proxy server | #shadowsocks #rust #proxy | Shadowsocks; AEAD ciphers; SIP002/2022",
    "shoes": "High-performance multi-protocol proxy server (Rust) | proxy server | #proxy #rust #server #multi-protocol | Multi-protocol proxy; CLI/config examples",
    "sing-box": "Universal proxy platform (SagerNet, Go) | proxy core | #singbox #proxy-core #go | VMess/VLESS/Trojan/SS/Hysteria/TUIC/Snell/WireGuard; TCP/WS/HTTP/gRPC/QUIC; DoH/DoT/fake-ip DNS",
    "sing-mux": "Simple stream multiplex library (Go) | multiplexing | #mux #multiplex #go #singbox | Stream multiplexing; session management",
    "smux": "Stream multiplexer for Go (sing-box mod) | multiplexing | #mux #multiplex #go | Stream-oriented multiplexing over TCP/UDS",
    "sniffnet": "Network traffic monitor (Rust) | network monitoring | #network-monitor #rust #tui | Packet capture; traffic stats; cross-platform",
    "soar": "DNS tunnel for censored networks (Getlantern, Go) | DNS tunnel | #dns-tunnel #censorship #go #quic | DNS tunneling; QUIC; L1 obfuscation",
    "starrocks": "Launcher/manager for StarRocks nodes (private internal) | internal tooling | #starrocks #internal #launcher | StarRocks node management (private GitLab)",
    "StormDNS": "TCP-over-DNS tunnel with local SOCKS5 (Go) | DNS tunnel | #dns-tunnel #tcp #socks5 #go | DNS query/response tunneling; SOCKS5; raw TCP listener",
    "sub-healer": "Local subscription-healing research (Rust) | local research | #subscription #local-research #rust | Subscription repair (local-only HEAD; not upstream)",
    "subconverter": "Proxy subscription format converter (C++) | subscription tool | #subscriptions #converter #cpp | Multiple subscription formats; Clash/Surge/V2Ray output",
    "tls-fingerprint": "Rust TLS ClientHello/fingerprint crate (frozen source) | TLS library | #tls #fingerprint #rust #leas-source | ClientHello construction; TLS 1.3 secrets; HTTP/2 fingerprint; ported into leas-tls",
    "toasty": "Embedded database for Rust (tokio-rs) | database | #database #rust #embedded | Embedded SQL storage; derive APIs",
    "tracing_allocator": "Rust global allocator logging allocations to file | memory tooling | #allocator #memory #rust #tracing | GlobalAlloc; allocation logging",
    "trojan": "Trojan proxy over TLS (C++) | proxy server | #trojan #tls #cpp #proxy | Trojan protocol over TLS; unidentifiable proxy",
    "TrojanRust": "High-performance Trojan proxy in Rust (tokio) | proxy server | #trojan #rust #tokio #proxy | Trojan protocol; TLS; performance focus",
    "tui-widgets": "Widget collection for Ratatui | TUI widgets | #ratatui #widgets #tui #rust | Scrollview, QR code, scrollbar, popup, prompts, charts",
    "tuic": "QUIC-based low-latency proxy (Rust fork) | proxy server | #tuic #quic #rust #proxy | TUIC protocol; QUIC; low handshake overhead; routing/observability",
    "turso": "In-process SQLite-compatible database (Rust) | database | #database #sqlite #rust #turso | SQLite file format; SQL; Postgres wire frontend",
    "unbihex": "Russian VPN client on own Rust core, Xray-compatible | desktop VPN client | #vpn-client #rust #xray-compatible | VLESS (TLS/REALITY/Vision/XHTTP/WS/HTTPUpgrade/gRPC); VMess (TCP/TLS/WS/HTTPUpgrade)",
    "utls": "uTLS fork of Go crypto/tls with ClientHello fingerprinting | TLS library | #tls #ja3 #ja4 #fingerprint #go #clienthello | TLS 1.2/1.3; ClientHello fingerprint resistance; fake session tickets; ECH; BoringSSL padding",
    "v2ray-configs": "Bulk V2Ray configs (GONE - upstream 404, frozen) | subscription feed | #vpn-configs #gone #frozen | V2Ray config collection",
    "v2ray-core": "V2Fly core (Go) | proxy core | #v2ray #vmess #go #proxy-core | VMess; VLESS; SOCKS/HTTP inbound; TCP/WS/gRPC transports",
    "v2ray-core-legacy": "Original v2ray/v2ray-core, moved to v2fly | proxy core (legacy) | #v2ray #legacy #go | VMess; legacy V2Ray protocol suite",
    "v2ray-core-v4.38.3": "V2Fly core pinned at v4.38.3 | proxy core (pinned) | #v2ray #pinned-old #go | VMess/VLESS; legacy transports",
    "v2ray-plugin": "SIP003 Shadowsocks plugin based on v2ray (Go) | proxy plugin | #sip003 #shadowsocks #plugin #go | SIP003 plugin; WebSocket/QUIC plugin modes",
    "v2rayN": "GUI client for Windows/Linux/macOS (C#) | desktop GUI client | #desktop-gui #csharp #client | Xray and sing-box cores; SOCKS/HTTP inbound",
    "v2rayNG": "Android V2Ray client (Kotlin) | mobile VPN client | #android #mobile-client | Xray/v2fly cores; VLESS/VMess/Trojan/SS",
    "vpn-configs-for-russia": "Free VPN configs working in RU | subscription feed | #vpn-configs #russia | VLESS/VMess configs; subscription lists",
    "wireguard-go": "WireGuard implementation in Go | VPN | #wireguard #vpn #go | WireGuard protocol; Noise framework; UDP",
    "wreq-util": "Utilities for the wreq HTTP client (Rust) | HTTP client utils | #http-client #rust #wreq | HTTP client helpers; browser-impersonation adjacent",
    "xrat": "Terminal CLI/TUI/Web UI proxy tester + subscription manager (Rust) | proxy manager | #tui #cli #proxy-tester #rust | Subscription import; proxy testing; saved results",
    "xray-checker": "Proxy availability monitoring with Prometheus (Go) | monitoring | #monitoring #xray #prometheus #go | VLESS/VMess/Trojan/SS probing; Prometheus metrics",
    "xray-config-toolkit": "Xray config builder / Iranian-site bypass | config tool | #config-tool #xray #iran | Xray configs; subscription links; bypass rulesets",
    "Xray-core": "XTLS Xray-core network tools (Go) | proxy core | #xray #xtls #go #proxy-core | VLESS; VMess; Trojan; SS; REALITY; XTLS Vision; XHTTP; TCP/WS/gRPC/QUIC",
    "xray-rs-tls": "Rust TLS/obfuscation experiment (frozen source) | TLS experiment | #tls #rust #xray #obfuscation | Referenced by leas-native salamander.rs",
    "yamux": "Yet Another Multiplexer for Go | multiplexing | #yamux #mux #go | Stream-oriented multiplexing over TCP/UDS",
    "zellij": "Terminal workspace / multiplexer (Rust) | terminal multiplexer | #terminal #multiplexer #rust #tui | Panes/tabs; terminal multiplexing (local edits)",
    "ZeroNet": "Persian VPN client on Rust 'Zray' core | VPN client | #vpn-client #rust #persian | VPN protocols; Zray core (local edits)",
}


def curated(name: str) -> tuple[str, str, str, str]:
    raw = CURATION.get(name)
    if not raw:
        return ("", "", "", "")
    parts = [p.strip() for p in raw.split("|")]
    return (parts + ["", "", "", ""])[:4]


@final
@dataclass
class Entry:
    name: str
    kind: str                            # "git" | "artifact"
    remote: str = ""
    ref: str = ""                        # tag or exact revision, as written
    sha: str = ""                        # resolved 40-char commit
    host: str = "local"                  # github | gitlab | codeberg | private | local
    status: str = "reference"            # see STATUS_ORDER below
    shallow: bool = False
    frozen: bool = False
    notes: str = ""
    extra: dict[str, str] = field(default_factory=dict)


STATUS_ORDER = [
    "gone", "frozen", "private-host", "ad-hoc-research", "pinned-tag", "reference",
]


def git(args: list[str], cwd: Path) -> str:
    r = sp.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def classify(name: str, remote: str, sha: str, ref: str, shallow: bool, dirty: bool) -> Entry:
    host = "local"
    if "github.com" in remote:
        host = "github"
    elif "codeberg.org" in remote:
        host = "codeberg"
    elif "gitlab.com" in remote:
        host = "gitlab"
    elif "spectrumdata" in remote or remote.startswith("git@"):
        host = "private"

    if name in GONE:
        status = "gone"
    elif name in PRIVATE_HOSTS:
        status = "private-host"
    elif name in LOCAL_WORK or dirty:
        status = "ad-hoc-research"
    elif name in FROZEN_ARTIFACTS:
        status = "frozen"
    elif ref and re.fullmatch(r"v?\d[\w.\-+]*", ref) and not ref.startswith("refs/"):
        status = "pinned-tag"
    else:
        status = "reference"

    frozen = (
        name in GONE or name in FROZEN_ARTIFACTS or name in PRIVATE_HOSTS
        or name in LOCAL_WORK or dirty
    )
    notes = ""
    if name in GONE:
        notes = "Upstream GitHub repo returns 404; this is the only frozen copy."
    elif name in PRIVATE_HOSTS:
        notes = "Private/internal host; not probeable via public API."
    elif name == "sub-healer":
        notes = "HEAD commit is not on upstream (local/rewritten); local edits present."
    elif dirty:
        notes = "Uncommitted local changes; pinned sha is the committed HEAD."
    if name in SUPERSEDED:
        notes = (notes + "; " if notes else "") + SUPERSEDED[name]

    what, domain, tags, standards = curated(name)
    extra: dict[str, str] = {}
    if what:
        extra.update(what=what, domain=domain, tags=tags, standards=standards)

    return Entry(
        name=name, kind="git", remote=remote, ref=ref, sha=sha, host=host,
        status=status, shallow=shallow, frozen=frozen, notes=notes, extra=extra,
    )


def scan() -> list[Entry]:
    """Build the entry list from the CURRENT on-disk state (no network)."""
    entries: list[Entry] = []
    for p in sorted(THIRDPARTY.iterdir(), key=lambda x: x.name.lower()):
        if p.name == "INDEX.md":
            continue
        if p.is_dir() and (p / ".git").exists():
            remote = git(["remote", "get-url", "origin"], p)
            sha = git(["rev-parse", "HEAD"], p)
            ref = git(["describe", "--tags", "--exact-match", "HEAD"], p)
            if not ref:
                ref = git(["symbolic-ref", "--short", "HEAD"], p) or "HEAD"
                ref = f"{ref}@{sha[:12]}"
            shallow = git(["rev-parse", "--is-shallow-repository"], p) == "true"
            dirty = bool(git(["status", "--porcelain"], p))
            entries.append(classify(p.name, remote, sha, ref, shallow, dirty))
        elif p.name in FROZEN_ARTIFACTS:
            what, domain, tags, standards = curated(p.name)
            extra = {"path": p.name}
            if what:
                extra.update(what=what, domain=domain, tags=tags, standards=standards)
            entries.append(Entry(
                name=p.name, kind="artifact", host="local", status="frozen",
                frozen=True, notes=FROZEN_ARTIFACTS[p.name], extra=extra,
            ))
        else:
            # Any other non-git leftover: keep it visible, never auto-delete.
            entries.append(Entry(
                name=p.name, kind="artifact", host="local", status="ad-hoc-research",
                notes="Unclassified non-git entry; kept as-is.", extra={"path": p.name},
            ))
    return entries


def render_index(entries: list[Entry]) -> str:
    by_status: dict[str, list[Entry]] = {s: [] for s in STATUS_ORDER}
    for e in entries:
        by_status.setdefault(e.status, []).append(e)

    lines = [
        "# thirdparty/ reference index",
        "",
        "Read-only reference material for **leas**. Nothing here is built, linked, or",
        "shipped. Source of truth for pins is [`thirdparty.toml`](../thirdparty.toml)",
        "at the repo root: every tag / exact revision plus its resolved sha, committed",
        "so `git log -p -- thirdparty.toml` is the full history of referencing.",
        "",
        "## Commands",
        "",
        "| command | effect |",
        "| --- | --- |",
        "| `python3 refresh.py` | default; read-only drift report (no clone/fetch/delete) |",
        "| `python3 refresh.py --probe` | + upstream existence via GitHub API (`UV_GITHUB_TOKEN`) |",
        "| `python3 refresh.py --sync` | rebuild manifest AND index **from disk** — overwrites hand edits |",
        "| `python3 refresh.py --index` | regenerate only this INDEX **from the manifest** (safe after a hand edit) |",
        "| `python3 refresh.py --apply` | reconcile non-frozen drifts to pinned sha (destructive; never touches frozen) |",
        "",
        "`.gitignore` ignores `thirdparty/**` but whitelists `*.md`, so this INDEX is",
        "tracked and the repo contents are not.",
        "",
        "## Status legend",
        "",
        "| status | meaning |",
        "| --- | --- |",
        "| `reference` | normal upstream-tracked git repo, pinned to a branch HEAD sha |",
        "| `pinned-tag` | pinned to an exact release tag |",
        "| `ad-hoc-research` | local work or origin drift; kept frozen, never refreshed |",
        "| `frozen` | non-git local snapshot; no upstream, never refreshed |",
        "| `gone` | upstream vanished (GitHub 404); only frozen copy |",
        "| `private-host` | private/internal git host, not probeable via public API |",
        "",
        "Frozen, gone, private-host and ad-hoc-research entries are **never** modified",
        "by `--apply`. Treat them as archival.",
        "",
        "## What each folder is (purpose · domain · tags · standards)",
        "",
        "Each tag is a search hint: scan the `#hashtags` column to jump to the right",
        "folder for a protocol, transport, RFC, or tech domain. Details live in the",
        "committed manifest (`what` / `domain` / `tags` / `standards` per entry).",
        "",
        "| folder | what it is | domain | tags | protocols / RFCs / transports |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in sorted(entries, key=lambda x: x.name.lower()):
        what = e.extra.get("what", "")
        domain = e.extra.get("domain", "")
        tags = e.extra.get("tags", "")
        standards = e.extra.get("standards", "")
        if not what:
            what, domain, tags, standards = curated(e.name)
        if not what:
            what = e.notes or "local reference snapshot"
        cells = [c.replace("|", "\\|") for c in (what, domain, tags, standards)]
        lines.append(f"| `{e.name}` | " + " | ".join(cells) + " |")

    lines += ["", "## Pins (exact tag / revision per entry)", ""]
    lines += [
        f"Total: {len(entries)} ("
        + ", ".join(f"{s}: {len(by_status.get(s, []))}" for s in STATUS_ORDER)
        + ")",
        "",
        "| folder | kind | status | host | ref | sha |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for e in sorted(entries, key=lambda x: x.name.lower()):
        ref = (e.ref or "-").replace("|", "\\|")
        sha = e.sha[:12] if e.sha else "-"
        lines.append(
            f"| `{e.name}` | {e.kind} | {e.status} | {e.host} | "
            f"`{ref}` | `{sha}` |"
        )
    lines += ["", "## Frozen / archival detail", ""]
    for e in sorted((x for x in entries if x.frozen), key=lambda x: x.name.lower()):
        lines.append(f"- **`{e.name}`** ({e.status}) — {e.notes or 'no upstream; kept as-is.'}")
    lines += [
        "",
        "## Conventions",
        "",
        "- One top-level folder per repo. Shallow clones (`--depth 1`) are the norm;",
        "  `shallow` is recorded in the manifest.",
        "- Change a pin: edit `thirdparty.toml`, then `python3 refresh.py --index`",
        "  (do NOT run `--sync` — it rebuilds the manifest from disk and loses edits).",
        "  Commit with a message that says why the revision changed.",
        "- Add a repo: clone under `thirdparty/`, run `--sync`, commit both files.",
        "- Remove a repo: delete its folder, run `--sync`, commit. Never `rm` inside",
        "  a frozen folder.",
        "- `tls-engine/` was flattened: its 4 repos are now top-level `geektls`,",
        "  `purecrypto`, `curl-impersonate`, `utls` (the last two replaced older copies;",
        "  superseded SHAs are in the manifest `notes`). Research docs that still cite",
        "  `thirdparty/tls-engine/*` are historical — resolve them via this INDEX.",
        "",
    ]
    return "\n".join(lines)


# ---- TOML (stdlib tomllib for reading; tiny writer, no third-party dep) ----

def toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def render(entries: list[Entry]) -> str:
    out = [
        "# thirdparty pin manifest -- committed; `git log -p -- thirdparty.toml` is the",
        "# full history of which tag / revision each reference pointed at, and when.",
        "# Regenerate from disk with: python3 refresh.py --sync",
        f"# generated: {date.today().isoformat()}",
        "",
        'schema = 1',
        "",
    ]
    for e in entries:
        out.append("[[entry]]")
        out.append(f"name = {toml_str(e.name)}")
        out.append(f"kind = {toml_str(e.kind)}")
        out.append(f"status = {toml_str(e.status)}")
        out.append(f"host = {toml_str(e.host)}")
        out.append(f"frozen = {'true' if e.frozen else 'false'}")
        if e.remote:
            out.append(f"remote = {toml_str(e.remote)}")
        if e.ref:
            out.append(f"ref = {toml_str(e.ref)}")
        if e.sha:
            out.append(f"sha = {toml_str(e.sha)}")
        if e.kind == "git":
            out.append(f"shallow = {'true' if e.shallow else 'false'}")
        if e.notes:
            out.append(f"notes = {toml_str(e.notes)}")
        for k, v in e.extra.items():
            out.append(f"{k} = {toml_str(v)}")
        out.append("")
    return "\n".join(out)


def load() -> list[Entry]:
    import tomllib
    if not MANIFEST.exists():
        return []
    data = tomllib.loads(MANIFEST.read_text())
    out = []
    for d in data.get("entry", []):
        known = {"name", "kind", "status", "host", "frozen", "remote", "ref",
                 "sha", "shallow", "notes"}
        extra = {k: v for k, v in d.items() if k not in known}
        out.append(Entry(
            name=d["name"], kind=d["kind"], status=d.get("status", "reference"),
            host=d.get("host", "local"), frozen=d.get("frozen", False),
            remote=d.get("remote", ""), ref=d.get("ref", ""), sha=d.get("sha", ""),
            shallow=d.get("shallow", False), notes=d.get("notes", ""), extra=extra,
        ))
    return out


# ---- GitHub probe (read-only) ----------------------------------------------

def slug(remote: str) -> str | None:
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", remote)
    return m.group(1) if m else None


def probe(entries: list[Entry]) -> dict[str, str]:
    token = os.environ.get("UV_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    result: dict[str, str] = {}
    targets = [e for e in entries if e.kind == "git" and e.host == "github" and slug(e.remote)]
    if not token:
        return {e.name: "no-token" for e in targets}
    for e in targets:
        s = slug(e.remote)
        req = urllib.request.Request(
            f"https://api.github.com/repos/{s}",
            headers={"Authorization": "Bearer " + token,
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "leas-thirdparty-refresh"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.load(r)
                result[e.name] = "ok" if not d.get("archived") else "archived"
        except urllib.error.HTTPError as ex:
            result[e.name] = "gone(404)" if ex.code == 404 else f"http-{ex.code}"
        except Exception as ex:  # noqa: BLE001 - probe is best-effort by design
            result[e.name] = f"error:{type(ex).__name__}"
    return result


# ---- commands --------------------------------------------------------------

def cmd_sync() -> int:
    entries = scan()
    MANIFEST.write_text(render(entries))
    INDEX.write_text(render_index(entries))
    print(f"[sync] wrote {MANIFEST.relative_to(ROOT)} with {len(entries)} entries")
    print(f"[sync] wrote {INDEX.relative_to(ROOT)}")
    print("       commit both: git add thirdparty.toml thirdparty/INDEX.md && "
          "git commit -m 'chore(thirdparty): pin reference revisions'")
    return 0



def cmd_index() -> int:
    """Regenerate INDEX.md from the committed manifest (never touches disk state)."""
    entries = load()
    if not entries:
        print("[index] no manifest -- run `python3 refresh.py --sync` first", file=sys.stderr)
        return 2
    INDEX.write_text(render_index(entries))
    print(f"[index] wrote {INDEX.relative_to(ROOT)} from {MANIFEST.relative_to(ROOT)} "
          f"({len(entries)} entries)")
    return 0

def cmd_report(entries_manifest: list[Entry], do_probe: bool) -> int:
    disk = {e.name: e for e in scan()}
    man = {e.name: e for e in entries_manifest}
    drift = 0

    if not man:
        print("[report] no manifest -- run `python3 refresh.py --sync` first")
        return 2

    print(f"[report] manifest={len(man)} entries, disk={len(disk)} entries (read-only)\n")
    print(f"{'name':34s} {'status':16s} {'ref / sha':30s} verdict")
    print("-" * 96)

    for name in sorted(set(man) | set(disk)):
        m, d = man.get(name), disk.get(name)
        if m and not d:
            print(f"{name:34s} {m.status:16s} {'-':30s} MISSING-ON-DISK")
            drift += 1
            continue
        if d and not m:
            print(f"{name:34s} {d.status:16s} {'-':30s} UNMANAGED (add via --sync)")
            drift += 1
            continue
        assert m and d
        tag = (d.ref or d.sha[:12] or "-")[:30]
        if m.sha and d.sha and m.sha != d.sha:
            verdict = f"DRIFT sha {m.sha[:8]}->{d.sha[:8]}"
            drift += 1
        elif m.ref != d.ref and m.status != "ad-hoc-research":
            verdict = "REF-CHANGED"
            drift += 1
        elif d.frozen:
            verdict = "frozen (never refreshed)"
        else:
            verdict = "ok"
        print(f"{name:34s} {d.status:16s} {tag:30s} {verdict}")

    if do_probe:
        print("\n[probe] upstream existence (read-only GitHub API):")
        pr = probe([d for d in disk.values()])
        for name in sorted(pr):
            flag = " <-- GONE" if pr[name].startswith("gone") else ""
            print(f"  {name:34s} {pr[name]}{flag}")

    print(f"\n[report] {'clean' if drift == 0 else f'{drift} drifted/undocumented'}")
    print("[report] dry-run: no clone/fetch/delete performed. "
          "Use --apply to reconcile non-frozen drift, --sync to refresh the manifest.")
    return 1 if drift else 0


def cmd_apply(entries: list[Entry]) -> int:
    """Only destructive path: reconcile non-frozen git entries to their pinned sha."""
    disk = {e.name: e for e in scan()}
    changed = 0
    for m in entries:
        if m.frozen or m.kind != "git":
            continue
        d = disk.get(m.name)
        if not d:
            print(f"[apply] SKIP missing {m.name} (dry-run policy: no re-clone). "
                  "Clone manually or add it back.")
            continue
        if m.sha and d.sha and m.sha != d.sha:
            print(f"[apply] {m.name}: fetch + checkout {m.sha[:12]}")
            sp.run(["git", "fetch", "--depth", "1", "origin", m.sha],
                   cwd=THIRDPARTY / m.name, check=False)
            r = sp.run(["git", "checkout", "--detach", m.sha],
                       cwd=THIRDPARTY / m.name, capture_output=True, text=True)
            print("   ", "ok" if r.returncode == 0 else r.stderr.strip()[:120])
            changed += 1
    print(f"[apply] reconciled {changed} entr{'y' if changed == 1 else 'ies'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Inventory/drift-check thirdparty/ against the committed pin manifest.")
    ap.add_argument("--sync", action="store_true",
                    help="rebuild thirdparty.toml from current on-disk state")
    ap.add_argument("--index", action="store_true",
                    help="regenerate INDEX.md from the committed manifest (not from disk)")
    ap.add_argument("--apply", action="store_true",
                    help="reconcile non-frozen git entries to their pinned sha (destructive)")
    ap.add_argument("--probe", action="store_true",
                    help="also check upstream GitHub existence (read-only API)")
    args = ap.parse_args(argv)

    if sum((args.sync, args.index, args.apply)) > 1:
        print("error: --sync, --index and --apply are mutually exclusive", file=sys.stderr)
        return 2
    if args.sync:
        return cmd_sync()
    if args.index:
        return cmd_index()
    entries = load()
    if args.apply:
        return cmd_apply(entries)
    return cmd_report(entries, args.probe)


if __name__ == "__main__":
    raise SystemExit(main())
