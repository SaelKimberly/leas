# The Real Test (All) funnel: 120 405 probed links, 14 completed tunnels

Evidence study, 2026-11-19. Snapshot: a copy of `~/.config/leas/data.db`
(+ `-wal`) taken while the app was running, schema 21 (`PRAGMA user_version` =
21): 65 158 `endpoints`, 77 533 `protocols`, 120 405 links (one
`profile_stats` row each). Every count below is from that copy, so the numbers
are internally consistent even though the live file keeps changing. Probe
settings from `config.json` at snapshot time: `real_ping_concurrency` 100,
`tcp_timeout_secs` 5 s, `real_ping_timeout_secs` 5 s, `real_ping_retries` 2,
`ping_url` = `https://www.gstatic.com/generate_204`, `ip_provider` = ip-api.

The run finished inside 2026-11-19; the DB has no probe timestamps, only
write-behind flush stamps (see §6), so per-minute throughput is not derivable
and is not claimed below.

Every count is a query over that file; the ladder that produces the funnel is
in §7. Code paths are cited by file and line at this commit.

## 1. Headline

| Fact | Value |
| --- | --- |
| Links with a stored measurement | 120 405 |
| Links whose tunnel carried a completed target handshake | **14** |
| Endpoints owning one of those 14 | 8 |
| Endpoints ranked Alive (`endpoint_rank.band` 0, `rank_alive` 1) | **7** |
| Links with a transport measurement (the endpoint answered the dial) | 55 531 |
| Links that never got a TCP connection or a name | 63 697 |

The user-visible "~7 working" is the rank band, and it is exact: 7 endpoints
carry `rank_alive = 1`. It is one lower than the 8 endpoints with a successful
real probe because one of them (`utiltools.site:443`, real delay 407 ms) sits in
band 2 — Purgatory, stale: its source stopped listing it, so the freshness gate
retired it even though it works. That is the retention law doing its job, not a
statistics fault.

The 14 successes sit on 8 endpoints, and the exit IP the probe recorded shows
how much duplication that hides: 10 of the 14 carry one, and 6 of those 10
report the same exit (`185.126.67.33`, the `falmero.store:443` links plus three
unnamed `:443` ws/tls links). The 4 without an exit IP cannot be deduped at
all, so "how many distinct servers work" is not answerable from this DB — only
"how many links report a working tunnel".

## 2. The funnel

Buckets are mutually exclusive and ordered; every link lands in exactly one.

| # | Outcome | Links | % | Endpoints | Purge verdict |
| --- | --- | ---: | ---: | ---: | ---: |
| 00 | never probed (no marker) | 390 | 0.3 | 178 | 15 |
| | — of which **completed target handshake** | **14** | | 8 | |
| 01 | engine cannot test (capability marker) | 752 | 0.6 | 509 | 19 |
| 02 | name does not resolve (`EAI_NONAME`) | 12 913 | 10.7 | 6 703 | **0** |
| 03 | TCP connect timed out (5 s) | 39 716 | 33.0 | 24 445 | 28 |
| 04 | TCP refused / unreachable / reset | 11 068 | 9.2 | 8 045 | 7 |
| 05 | TCP up, tunnel timed out at the target handshake | 23 778 | 19.7 | 11 055 | 83 |
| 06 | REALITY fell back to the real certificate | 3 422 | 2.8 | 1 124 | 3 290 |
| 07 | certificate invalid / expired / wrong name | 2 041 | 1.7 | 505 | 1 814 |
| 08 | TLS alert (handshake_failure 6 811, internal_error 288, unrecognized_name 240) | 7 366 | 6.1 | 5 011 | 5 |
| 09 | HTTP status from the transport front (403/409/500/530/…/200) | 14 889 | 12.4 | 8 121 | 8 005 |
| 10 | config defect (unparsable URI, unusable shape) | 418 | 0.3 | 256 | 418 |
| 11 | tunnel opened then broke (truncated VLESS header, early EOF, non-TLS first byte) | 2 294 | 1.9 | 1 331 | 1 |
| 12 | other | 1 358 | 1.1 | 876 | 215 |
| | **total** | **120 405** | 100 | 65 158* | 13 900 |

\* endpoints are the DB total, not a column sum: a multi-link endpoint appears
in every bucket one of its links landed in.

Two ways to read the same table:

- **Reachability**: 52.9 % of links (63 697) never got a TCP connection or a
  name; 46.1 % (55 531) did, and of those 42.8 % (23 741) then died at the
  target handshake.
- **Verdicts**: 11.6 % of failures (13 900 / 120 053) carry a purge verdict.
  The classes that earn one are the ones the origin answered by name
  (REALITY fallback, certificate, proxy 4xx, config defect). Everything a
  timeout or a 5xx produced stays live and is re-probed on every run, and a
  name failure stays live until a batch or the manual retry re-resolves it.

## 3. What each large bucket actually is

**02 — name does not resolve (12 913 links, 10.7 %).** The only stored fact is
one `error_text` string: the C library's message for `failed to lookup address
information` — in this snapshot that is always "Name or service not known", and
**no row holds any other resolver text** (zero rows with a `No address
associated`/`EAI_NODATA`-style message). The column keeps no resolver status
code, so a permanent answer and a temporary one are indistinguishable in the DB
unless the runtime message differs, and here it never does.
It is **not** a stable verdict, and the live DB proves it: of the 6 703 endpoints
carrying this marker, **102 (336 links) already resolve again** — addresses are
in `endpoint_ip`, the marker is still `[name]`, because only a probe clears it.
A manual "Retry Failed DNS Lookups" (`crates/leas/src/ops/compact.rs:399-475`)
turns another **~20–30 hosts per run** from unresolvable to resolvable (user
observation, 2026-11-19; not stored, see §8). The retry population is larger
than the marker: 9 836 DNS endpoints have no address row, 3 235 of which never
carried a DNS failure at all (imported and never resolved). Part of any retry
trickle is therefore import churn rather than revival, and the DB stores no
fact that separates the two.

The retry only *resolves*: it filters endpoints with an empty address set
(`compact.rs:439-446`), dispatches one resolver task per name
(`crates/leas/src/ops/events.rs:716-728`) and stops. It does not probe the link
and no writer clears a `name` marker on resolution — `apply_test_result` clears
a marker only on a probe result (`events.rs:150-283`). So a host that resolves
today keeps showing `[name]` until the next Test-All re-probes it.

The lesson for the statistics is the opposite of "retire it": a name failure is
a *probe-time state* with a decay rate, so it needs a retry cadence and an age,
not a verdict. If anything is retired here, it must be a time-limited verdict
(Purgatory's 7-day TTL) driven by a *repeated* permanent answer, never by the
first one.

**03 — TCP timeout (39 716, 33.0 %) and 04 — refused (11 068, 9.2 %).**
Batch dials only: `EngineProbeRunner::fast` runs `leas_core::FastPingManager`
(`crates/leas/src/ops/ping.rs:923-966`), and its own comment states the shape —
"A TCP handshake never reaches a protocol phase" (`ping.rs:939`). A timeout here
is one number: the SYN went unanswered for 5 s under 100 concurrent dials. In a
filtered network (RU ruleset, many `.ir` origins) a filtered IP and a dead IP
produce the identical row. 24 445 distinct endpoints is 37 % of the DB, so the
false-negative rate of this bucket is the single largest unknown in the
headline.

**05 — target timeout (23 778, 19.7 %).** The tunnel opened (transport span
median 27 ms on the successes, <1 s on 54 454 of 55 531 transport spans) and the
TLS handshake to `gstatic.com:204` never finished inside 5 s. This is the bucket
where a working server and a broken measurement look identical, because the
stage that failed is the *target's* reachability through the exit, not the
server's own acceptance.

**08 — TLS alert (7 366, 6.1 %).** `alert: 2 40` (handshake_failure) dominates.
The peer's TLS stack received the ClientHello and refused it. That is a
statement about the config (SNI/ALPN/fingerprint/flow mismatch) or about active
filtering — not a statement the current taxonomy can express, so all 7 366 stay
live.

**09 — HTTP status (14 889, 12.4 %).** `403` (2 551), `409` (3 216), `500`
(2 679), `530` (1 272), `404` (606), `503` (454), `429` (280), `412` (212), plus
312 rows whose WebSocket upgrade was answered `200 OK` — the front treated the
upgrade as a plain request. The 4xx family is classified
(`TransportRejected`); `409`/`530`/`500`/`503`/`429`/`412` are deliberately
excluded as transient or CDN-side policy, which leaves 6 884 links re-probed
forever.

**06 — REALITY fallback (3 422) and 07 — certificate (2 041).** Correctly
purged (3 290 / 1 814): the peer presented a real certificate where REALITY was
asked for, or a certificate that does not name the SNI. These are the classes
the verdict system was built for and they work.

**01 — engine cannot test (752 links, 509 endpoints).** The gate refused 12
distinct reasons; §3.2 grades every one against the §3.1 rule and lists the
oracle matrix per class. In short: **548 are not configs at all** (490 rows
carry a marker text the current binary cannot emit; 58 are `ss://null:null`
placeholders), **51 are a policy decision** (SOCKS5, whose client already
ships), and **148 are accepted by at least one of the three pinned oracles** —
so none of them may be retired on the strength of one core's refusal.

**11 — tunnel/framing (2 294).** `vless response version 0x48: not a VLESS
response header` (491), `vless response header truncated (EOF)` (925),
`expected Handshake record (0x16)` (83). The last one is interesting: all 83
also carry `latency_auth = ok`, i.e. the server answered the protocol header
and then delivered something that is not a TLS record — an egress-side answer,
not a config rejection. Only 1 of 2 294 rows carries a verdict.

### 3.1 The deprecation rule this inventory is graded against

Project rule (2026-11-19): a protocol, config, cipher or flow variant is
deprecated only for one of two reasons — **large sources no longer carry it**
(measured absence, not an upstream changelog), or **upstream designates it
unsafe, harmful or highly detectable, with evidence**. Upstream merely removing
it is not a reason, and neither is code size or resource cost: this is a client,
so a legacy variant stays supported while a peer still speaks it. A config
judged *insecure* is refused at ingestion and never stored; one already stored
earns a verdict, moves to Purgatory and is purged by the existing TTL (7 days).

Two precedents already in the tree: `ss` method `none` on a cleartext wire is
refused at ingest (`crates/leas-config/src/import_export.rs:168-174`) — reason 2;
the VLESS `encryption` validation (2026-11-18) is the *invalid value* axis, which
is not deprecation at all.

**Peer evidence is not a ground.** This project tests against three pinned
oracles — xray-core, sing-box and mihomo — so "xray refuses it" decides nothing.
Every row below carries an oracle matrix, and only the two reasons above decide:
one oracle's refusal cannot retire a variant another oracle serves today.

### 3.2 The `engine cannot test` inventory

Counts are this snapshot's links/endpoints. Each note carries the row's status
under §3.1, and every peer claim is a three-oracle matrix (xray-core, sing-box,
mihomo) rather than one core's behaviour.

| # | Marker (stored text, prefix dropped) | Links | Eps | What exists today | Note |
| --- | --- | ---: | ---: | --- | --- |
| 1 | `vless account encryption is not implemented` | 490 | 280 | mlkem account encryption **is** implemented (`capability.rs` module doc: supported since 2026-09-23); `VlessConfig::validate` refuses only an *invalid* value and names it | **Status: stale marker over an invalid value** (ingest already refuses it). The shipped binary cannot produce this string (`strings target/release/leas` finds none; the gate emits ``vless encryption `<value>` is not a VLESS encryption value`` instead). The stored values are 457 empty and 25 SS ciphers (`chacha20-poly1305`, `aes-128-gcm`), all invalid under the current rule. The marker survives because the whole bucket has no transport span: the fast dial fails first, so the real phase (the only place the gate runs) never re-gates the row. |
| 2 | `shadowsocks 2022 multi-user PSK list is not implemented` | 89 | 61 | single-user BLAKE3-2022 (`2022-blake3-aes-128/256-gcm`) | **Status: keep — live upstream, implement.** The row is **valid**, not malformed: xray's client form is a `:`-separated PSK list (`thirdparty/Xray-core/proxy/shadowsocks_2022` is present), and native has no multi-user identity rule. Needs the key-selection semantics pinned from xray before any code. |
| 3 | `shadowsocks method is not implemented` | 58 | 58 | `resolve_method` — the same function the dial uses, so gate and codec cannot drift | **Status: not a config — drop at ingest.** Not a parser bug. All 58 come from one link shape in `avencores:14` (`.../githubmirror/14.txt`): `ss://bnVsbDpudWxs@<host>:<port>#https%3A%2F%2Ft.me%2Fallproconf`, and `bnVsbDpudWxs` base64-decodes to exactly `null:null` — the feed's generator serialised an unset cipher and password. `SsConfig::try_parse_proto` stores `method: "null"`, `password: "null"` faithfully (`ss.rs:113-176`). The 58 feed placeholders match the 58 rows (port sets identical); 49 of the endpoints also carry a real link (mostly vless on the same host:port), so 9 endpoints exist only because of the placeholder. See §5.9 for the ingestion fix. |
| 4 | `no native implementation for this protocol kind` — `socks` | 51 | 51 | a 585-line SOCKS5 **client** (`protocol/socks/mod.rs`, no-auth + RFC 1929), already in the dispatch (`protocol/mod.rs:184`) | **Status: keep — gate only.** `kind_supported` excludes `Socks` and the test `non_native_kinds_unsupported` pins the exclusion, while the connect path serves it. Both pinned cores still serve SOCKS5 (`thirdparty/Xray-core/proxy/socks`, `sing-box/protocol/socks`), so nothing justifies dropping it. TCP CONNECT only (no UDP ASSOCIATE). Cheapest capability win here: a policy decision plus oracle validation, no new protocol code. |
| 5 | same — `wire_guard` | 10 | 10 | placeholder (`protocol/wireguard/`, 2 lines) | **Status: keep — live upstream, implement.** Missing: Noise IK handshake, its own UDP device socket, timer state machine (`thirdparty/Xray-core/proxy/wireguard` and `sing-box/protocol/wireguard` both serve it). Largest item in the table. |
| 6 | same — `tuic` | 8 | 7 | placeholder (`protocol/tuic/`, 2 lines); `quinn` already in the crate for hysteria2 and xhttp-h3 | **Status: keep — live upstream, implement.** Missing layer over an existing QUIC stack (`quinn` is already in the crate): TUIC handshake + per-stream framing. `sing-box/protocol/tuic` serves it; xray does not. |
| 7 | same — `hysteria` (v1) | 1 | 1 | placeholder | **Status: keep — live upstream, implement.** Not obsolete: the pinned xray 26.x ships a `hysteria` transport and a `proxy/hysteria`, and sing-box ships `protocol/hysteria` (v1). One row here, but the earlier "obsolete" reading was wrong. |
| 8 | same — `http` | 1 | 1 | placeholder (`protocol/http/`, 2 lines) | **Status: keep — live upstream, implement.** HTTP CONNECT proxy + basic auth over the tunnel (`thirdparty/Xray-core/proxy/http`, `sing-box/protocol/http`). Small; one row in this feed sample. |
| 9 | `vless flow is not implemented` | 29 | 28 | the vision pair only | 22 `xtls-rprx-direct`, 2 `-udp443`, 1 `xtls-rprx-origin`. **Status: keep — community-thin.** Oracle matrix: **xray 26.x refuses** the flow at config time on both sides (`infra/conf/vless.go:51`, `:331`); **sing-box accepts** — the flow is handed straight to `vless.NewClient` (`protocol/vless/outbound.go:95`) and the inbound only reads it for a KTLS optimisation (`inbound.go:79`); **mihomo accepts and dials any non-vision flow as plain VLESS** (`transport/vless/conn.go:168-176` special-cases only `XRV`). So 2 of 3 oracles still accept it — the only ground for retiring the class would be reason 1, and it is thin: 25 of 120 405 links (0.02 %). Not a safety finding. **What "accept" means here:** sing-box and mihomo transmit the flow addon and dial plain VLESS; neither implements the XTLS direct/origin splice, so no pinned oracle honours the flow's semantics end to end, and the class is *accepted*, not *served* — liveness against a legacy XTLS server stays unproven; §3.4 dialled the whole corpus and found no live instance. 2 rows carry `flow=none`, an **alias** for *absent* worth normalising; 2 are **malformed** duplicate suffixes. Removal rationale checked — §3.3; corpus measured — §3.4. |
| 10 | `legacy vmess payload security is not implemented` | 13 | 13 | AEAD only (absent/`auto`/`aes-128-gcm`/`chacha20-poly1305`); legacy `alter_id` **is** dialled | **Status: keep — community-thin.** 12 rows are `enc: none`, 1 is `zero`. Oracle matrix: **xray 26.x refuses** (`SecurityType` enum, `common/protocol/headers.pb.go:35-46`); **sing-box accepts** — `security` is forwarded verbatim to `sing-vmess` (`protocol/vmess/outbound.go:99-106`) and its option enum lists `none,zero,aes-128-cfb,…` (`option/vmess.go:21`); **mihomo serves `none`** (`SecurityNone`, `transport/vmess/vmess.go:24-40`). So 2 of 3 oracles serve the class; retiring it would rest on reason 1 alone — 13 of 120 405 links (0.01 %). |
| 11 | ``vless multiplexer `muxtype=smux` …`` | 1 | 1 | muxcool / h2mux / smux / yamux | **Status: defect.** Message names `smux` while listing `smux` as allowed — one row, but the wording contradicts itself; worth one look. |
| 12 | `transport is not implemented` | 1 | 1 | tcp/ws/grpc/http/httpupgrade/xhttp(+h3)/kcp | **Status: keep — community-thin.** Oracle matrix: **sing-box serves it** (`thirdparty/sing-box/transport/v2rayquic`); **xray 26.x removed it** — `case "quic": return "", errors.PrintRemovedFeatureError(...)` (`infra/conf/transport_internet.go:37-38`); **mihomo has no such transport** in its outbound network set. One oracle still serves the shape, so only reason 1 applies: 1 of 120 405 links. Implementation is cheap if a source resurfaces (`quinn` is already in the crate). |

Sum: 752 links / 509 endpoints, in four groups under the §3.1 rule:

| Group | Links | What it is |
| --- | ---: | --- |
| Not a config | 548 | 490 stale VLESS-encryption markers over invalid values + 58 `null:null` feed placeholders |
| Gate only | 51 | SOCKS5 — implemented and dispatched, excluded by `kind_supported` |
| Keep — accepted by at least one oracle | 148 | 89 ss2022 multi-user, 25 non-vision VLESS flows (accepted by sing-box + mihomo, dialled as plain VLESS — semantics not implemented), 13 legacy VMess ciphers (sing-box + mihomo `none`, implemented), 10 WireGuard, 8 TUIC, 1 hysteria v1, 1 HTTP proxy, 1 `quic` transport (sing-box, implemented) |
| Aliases / defects | 5 | 2 `flow=none` aliases, 2 malformed flow suffixes, 1 self-contradicting mux message |

**No class here is deprecation-eligible on peer evidence.** Every class that one
oracle refuses is accepted by another — that is what the matrix column records,
and it is the reason the earlier "xray cannot, so it is dead" reading was
withdrawn. Accept is not the same as implement: legacy VMess ciphers and the
`quic` transport are *implemented* in sing-box (and `none` in mihomo), while the
non-vision VLESS flows are only *accepted* — sing-box and mihomo dial them as
plain VLESS without the XTLS splice, so no oracle demonstrates end-to-end
behaviour for that class (§6). Three classes are *community-thin* (39 links,
0.03 % of the corpus: 25 flows, 13 legacy VMess, 1 `quic` transport); reason 1
could be invoked for them as a deliberate decision, and this report records the
measurement without taking it.

Nothing in this band qualifies as *insecure* under reason 2: no pinned oracle
designates any of these variants unsafe, harmful or detectable. What the band
*is* today: 73 % accounting noise (548/752 not configs), one policy decision
(SOCKS5), and features the client simply has not written — the missing-work list
is **148 links across eight classes**, not 752.

### 3.3 Why the non-vision VLESS flows were removed (checked 2026-11-19)

The question was whether there is a reason to treat `xtls-rprx-direct` /
`-origin` as *insecure* and drop them at ingest. Sources, in order of authority
(quoted Chinese is translated; follow the links for the originals):

- **v1.7.5 release notes** (RPRX): "Xray-core v1.8.0 will add support for REALITY
  and may drop support for the legacy XTLS — please migrate to XTLS Vision as
  soon as possible." A migration notice tied to the REALITY pivot. No safety
  claim.
  <https://github.com/XTLS/Xray-core/releases/tag/v1.7.5>
- **Official docs** now list only `""`, `xtls-rprx-vision` and
  `xtls-rprx-vision-udp443`; direct/origin are simply absent, with no security
  statement. <https://xtls.github.io/config/outbounds/vless.html>
- **The security claim in circulation** ("XTLS Direct has been shown to carry a
  risk of active probing and attack", e.g. cascade.moe) traces to the "233"
  analysis in [XTLS/Go#17](https://github.com/XTLS/Go/issues/17). The author
  refuted it there (2023-02-27): "The relevant code exists only after the server
  has verified the client UUID, therefore it cannot be actively probed. This
  thread is closed." The Vision announcement thread's
  top reply repeats that the 233 probing claim does not exist, linking the same
  issue ([discussion #1295](https://github.com/XTLS/Xray-core/discussions/1295)).
- **The Vision write-up** is the closest thing to a detectability argument: the
  TLS-in-TLS handshake's five packets have obvious length and timing features,
  and Vision pads the short ones. But it is an argument about *unpadded
  TLS-in-TLS handshakes in general* — `flow=""` rows have exactly the same
  property, and they are most of this corpus — so using it to condemn
  direct/origin would condemn plain VLESS+TLS first. The same post quotes RPRX
  on Direct: "it can be implemented without patching the TLS library at all —
  very concise and efficient."
- **A fourth implementation** exists: v2fly-core v4.31.0 lists "Add XTLS Direct
  Mode" in its release notes
  (<https://github.com/v2fly/v2ray-core/releases/tag/v4.31.0>), so even the
  "no peer" reading fails outside the three oracles.

Verdict: **reason 2 is not satisfied.** No upstream source designates
direct/origin unsafe, harmful or highly detectable *with evidence*, and the one
concrete attack claim was refuted by the project author on mechanism. The class
stays `keep`; reason 1 (0.02 %) remains the only ground, which this report
records without taking. Caveat: this is a check of upstream statements, not an
independent audit, and the refutation is the author's argument rather than a
third-party analysis.

### 3.4 The flow-variant experiment (2026-11-19)

Decision rule applied: extract every link with a non-vision flow, try to
connect; if they all work only as plain VLESS, normalise the flow; if they are
all dead, retire them and refuse the shape at ingest; if even one speaks XTLS,
implement the flow natively. **Result: all dead.**

**Method.** All 29 links the gate marks `vless flow is not implemented` — 25
`direct`/`direct-udp443`/`origin`, 2 `flow=none`, 2 malformed vision suffixes —
read from the snapshot as `(host, port, uuid, flow, security)` (IP hosts decoded
from the packed `endpoint_ip.ip_key`). Pre-check: DNS + TCP connect. Then, per
target, a real dial through **Xray 1.7.5** — the last release that ships
`xtls-rprx-direct`/`-origin` — as a local SOCKS inbound + one VLESS outbound,
fetching `http://www.gstatic.com/generate_204` through the tunnel, in up to four
variants: flow as configured, plain (`flow=""`), and, for the TLS-bearing rows,
`security: "xtls"` (the only spelling 1.7.5 accepts XTLS under) and vision. The
plain variant is the exact wire sing-box and mihomo produce for these flows
(§3.2), so their dial is covered: it is the *strongest* case, because it omits
the flow addon entirely.

**Pre-check on the 28 unique targets.**

| Outcome | Targets |
| --- | ---: |
| name does not resolve | 18 |
| TCP refused | 3 |
| TCP accepted | 7 |

**Results — every dial failed, and the failure is the config, not the network.**

| Variant | Targets tried | Outcome |
| --- | ---: | --- |
| flow as configured (no `security`) | 6 | legacy core **refuses to dial**: `failed to use xtls-rprx-direct, maybe "security" is not "xtls"` |
| plain `flow=""`, no `security` | 6 | all fail: 4 × timeout, 2 × empty reply |
| `security: xtls`, flow `direct` / `direct-udp443` | 2 | empty reply |
| `security: tls`, flow `vision` / plain | 2 | empty reply |

Two facts follow, and the second is the one that matters.

1. **No server in this corpus speaks XTLS, plain VLESS, or vision.** 17 targets
   do not resolve; of the 7 that accept TCP, none completed a VLESS handshake in
   any variant. The corpus agrees: of the 14 links that ever completed a tunnel,
   **12 carry no flow and 2 carry vision + REALITY**; no non-vision-flow link has
   ever worked here.
2. **27 of the 29 links are not flow variants at all — they are invalid
   configs.** They set a flow with `security` empty. XTLS is defined only over
   TLS/REALITY (`xtls.github.io`: "XTLS is available only with TCP+TLS/REALITY"),
   so both the legacy and the current core refuse the shape itself — 1.7.5 at
   dial time with the message above, 26.x at config load. The two that *do*
   carry TLS point at `104.16.16.255` (Cloudflare anycast) and `1.0.0.0`, with SNI
   `vincent-jackson2021.ga` and a feed remark tagged `[UnResolvedDomains]` — a
   placeholder pair, dead in every variant.

The same defect exists on the vision side and is bigger: **58 links carry
`flow=xtls-rprx-vision` with no security layer**, and none of them has ever
worked. Flow-without-TLS is one invalid class, not two.

**Cross-check: would the missing layer rescue them?** A feed that drops
`security=` but keeps `flow=` would be repairable by implying the layer. Tested
the same day:

| Arm | Targets | Result |
| --- | ---: | --- |
| xray 1.7.5, implied TLS (SNI = host, insecure), flow as stored | 6 | 6 × fail (4 empty reply, 2 timeout) |
| sing-box 1.13.13, TLS on, **flow omitted** | 6 | 5 × fail — 2 Cloudflare endpoints answered in ~190 ms with a remote error (TLS completed, the VLESS layer refused), 1 EOF after 4.1 s, 3 timeouts |
| sing-box 1.13.13, TLS on, `flow=xtls-rprx-vision` | 6 | 6 × fail |

Certificates tell the same story from the other side: three of those endpoints
complete a TLS handshake with verify-ok, so TLS *is* served — the proxy layer is
what is missing. Reality cannot be reconstructed at all (25 of 27 rows carry no
`pbk`).

The decisive control holds as well: **none of the 14 links that ever succeeded
has an empty security layer** — 12 carry no flow but all are `tls`/`reality`, 2
are `vision` + `reality`. So "missing security ⇒ TLS" is consistent with the
corpus (a working plain-TCP VLESS has never been seen here) and still rescues
nothing: the reachable servers are dead, not misdeclared.

**Decision (recorded, not implemented here).**

- Do **not** implement `xtls-rprx-direct`/`-origin`: no live instance exists in
  this corpus to prove against, and §3.3 shows no safety ground either.
- Do **not** normalise the flow to plain, and do **not** imply a TLS/REALITY
  layer: the plain dial is dead on every reachable target and the implied-layer
  arms fail 6/6, 5/6 and 6/6 — normalisation would not rescue a single link here.
- The actionable rule is narrower than "non-vision flow": **a non-empty `flow`
  requires a TLS/REALITY layer** — the invalid combination covers 27 of these 29
  links *and* the 58 vision-without-TLS ones. New imports should be refused at
  ingest on that rule; the 85 stored links are failed probes with a config
  defect, so `config_invalid` is the natural verdict and Purgatory's TTL retires
  them.
- The 2 TLS-bearing `direct-udp443` links are valid configs on dead servers;
  they die by retention, not by a rule.

**Limits.** One vantage, one run, 29 links — the whole population this DB has.
`direct`/`origin` may still live on a server that none of these feeds carries;
the experiment shows the current corpus is empty, not that the flow is
unimplementable. Tooling was throwaway (`/tmp`, Xray 1.7.5 from GitHub
releases); nothing was committed and no repo code changed.

Note what the rule protects. The pinned xray 26.x prints *deprecation warnings*
(not removals) for the gRPC, WebSocket and HTTPUpgrade transports
(`thirdparty/Xray-core/infra/conf/transport_internet.go:25-35`), and this
snapshot alone carries 51 146 ws, 11 070 grpc and 1 827 httpupgrade links —
**64 043 of 120 405**. Keeping those is not legacy-code luxury; it is the
majority of the corpus. The same reading keeps the SS stream ciphers xray
dropped but sing-box still serves (`SINGBOX_SS_METHODS`): 470 `aes-256-cfb`
links here, and the native codecs already implement them.

The gate can also refuse shapes this DB never exercised (both counts are zero
here, so they are unmeasured, not absent): an invalid `ECHConfigList`
(`tls ech config is not a valid ECHConfigList`), a SIP003 plugin shape
(`shadowsocks SIP003 plugin is not implemented`, one verdict per key/value —
including `mode=quic`), an SS method family that does not match the kind, a
malformed 2022 PSK, `anytls: missing password`, `anytls: REALITY security does
not apply (TLS only)`, an unknown mKCP `header_type`, vision with an sbox mux,
`vless mux option … is not a supported cap`, and a kind/config type mismatch.

## 4. Measurement defects the run exposes

### 4.1 One error slot for a three-stage probe
`profile_stats` stores one `error` boolean, one `error_kind`
(`real`/`fast`/`name`, a frozen `CHECK` — a new value is a schema wipe,
`crates/leas/src/ops/ping.rs:74-88`) and one free-text `error_text`. The probe
has three stages (dial / transport handshake / protocol + target). So:

- the kind is the *last* writer's, not the deepest failure's;
- the class survives only as prose, capped at the boundary
  (`crates/leas/src/ops/events.rs:93-110`) and sometimes localized ("Попытка
  установить соединение была безуспешной…"), so any report over classes is a
  regex over English phrases;
- 455 links carry a measured real delay *and* a `fast` marker — intentional
  (`events.rs:186-206` keeps a stale measurement), but it means the Test cell,
  the rank ring and the delay columns disagree about the same link.

### 4.2 `latency_auth = ok` is stored and then ignored by the model
111 links carry `AuthAck::Ok`; 110 of them are live and 98 have a failure
marker. Read as evidence: the server accepted the config, the tunnel then
failed to carry the target handshake. That is the "valid config, broken egress"
class — exactly the partial credit that would let a report distinguish dead
configs from dead exits. Nothing consumes it: the rank does not, the report
does not, and the Test cell shows `[real]`.

### 4.3 Retries run concurrently, and the persisted failure is the last to finish
`probe_attempts` spawns `retries.max(1)` attempts into one `JoinSet`
(`crates/leas/src/ops/ping_native.rs:465-518`) and keeps `last_error` = whichever
attempt finished last (`ping_native.rs:520-554`, consumed at `:572-575`).
Consequences:

- in-flight tunnels are `real_ping_concurrency × attempts` = up to 200 at the
  configured values, all sharing one home uplink;
- the recorded class depends on completion order, not on which attempt produced
  the more informative evidence — a timeout can overwrite a protocol rejection;
- 5 s is the per-attempt budget, so the effective budget for a link is
  `max(attempts)`, not a sum.

### 4.4 The target stage dominates the span
The 14 successes took 226–5 394 ms; their transport spans were a median of
27 ms (12 of 14 under 32 ms, one 1 832 ms on the shadowsocks link). The
measured distribution of the *only* stage that can succeed sits inside the 5 s
cap by a factor of ~1, and the top three successes (2 867, 3 212, 5 394 ms) are
60–100 % of the budget. A 5 s cap cannot distinguish "slow exit to gstatic" from
"dead tunnel", and the run's 23 778 target timeouts are exactly that ambiguity.

### 4.5 A single target is a single point of false negatives
`gstatic.com:204` is one host on one network path from each exit. Any exit whose
route to gstatic is filtered, rate-limited or slow scores as a dead proxy even
if it carries traffic elsewhere. There is no second target and no
target-independent probe in the row.

### 4.6 "Alive" reads the newest ring sample only
`alive` is the representative link's newest ring sample
(`crates/leas-db/src/endpoint_rank.rs:579-583`), so a later 5 s dial timeout on a
link whose previous real probe succeeded flips the endpoint out of band 0. With
7 alive endpoints out of 65 158, one flake per endpoint is not noise.

### 4.7 Duplicate links inflate every denominator
1.85 links per endpoint (120 405 / 65 158). `latency_ip` is stored on only 847
rows (386 distinct exit IPs) and on 10 of the 14 successes, so the DB cannot
currently say "how many distinct servers work", which is the number a user
actually wants; the 6 links that share one exit IP are the visible part of the
duplication, not its size.

### 4.8 The `[name]` marker outlives the failure it records
`error_text` from bucket 02 is a snapshot of one `getaddrinfo` call. Nothing
clears it when the name later resolves: the retry writes `endpoint_ip` rows and
stops (`compact.rs:439-446` → `events.rs:716-728`), while the marker is cleared
only by a probe (`events.rs:150-283`). The only ageing mechanism is
`speed_test.error_ttl_hours` (`clear_expired_errors`,
`crates/leas/src/ops/profiles.rs:33-63`), which is all-or-nothing over every
marker kind and is disabled in this config (`null`). In the snapshot,
102 endpoints (336 links) are in exactly that state — a resolvable address set
and a `[name]` marker (counts from a second copy taken later the same day;
bucket 02 itself was unchanged). The user-observed ~20–30 resolutions per
manual retry means the stale set grows with every run. Any report that counts
`[name]` as dead is measuring the age of the last batch, not the feed. The
rank consequence is the one a user feels: the marker keeps the link in bin 13/14
(or 15 while the address set is empty), so a host that resolves today still
sorts behind every untested row and waits for the next full run — §5.2 is the
one-line fix.

## 5. Ways to raise the working-server count, ranked by evidence per unit work

1. **Re-probe the timeout cohorts at low concurrency, longer budget (no code).**
   63 697 dial failures and 23 778 target timeouts were produced at 100
   concurrent links × 2 concurrent attempts on one uplink. Re-run a sample (500
   per cohort) at `real_ping_concurrency` 4 with `tcp_timeout_secs` /
   `real_ping_timeout_secs` 15 s. The delta *is* the false-negative rate and
   costs one run. Do this before any conclusion about the feeds.
2. **A resolved name must fall back to "not tested", not stay at the bottom.**
   Today a successful resolve writes `endpoint_ip` and nothing else, so the
   link keeps its name-class marker (`fast` kind → bin 14, `name` kind → bin 13)
   and keeps sorting under every untested row. The ordering law already has the
   target state: clear the name-class marker on the endpoint's links once its
   address set becomes non-empty, then refresh the keys
   (`refresh_endpoint_ranks`, the shape `clear_expired_errors` already uses,
   `crates/leas/src/ops/profiles.rs:33-70`). The link lands in **bin 12
   ("untested")** and the endpoint enters the `New` scope
   (`rank_proven = 0 AND rank_bin = 12`) — the top of the `Test` order and the
   target of the "New" run, instead of the back of it. Precisely: `band`
   (0/1/2, alive/freshness) does not change; `bin` does. Only a name-class
   marker is cleared — a real verdict, a real error and a purge stay.
   Then (b) split the resolver statuses at the boundary (`EAI_AGAIN`/`EAI_FAIL`
   vs `EAI_NONAME`) so a temporary answer is never stored as a permanent one —
   the DB has no column for it today, which is the deeper reason a name failure
   cannot be classified after the fact. If a verdict is ever wanted here it must
   be TTL-limited and require a repeated permanent answer.
3. **Persist the stage and the typed class.** One nullable
   `failure_class TEXT` (CHECK'd, e.g. `dns|dial_timeout|dial_refused|
   tls_alert|http_status|target_timeout|framing|config`) written from
   `FailureEvidence`, not parsed from prose. Prerequisite for every number in
   §2 being reproducible without regex; the `error_kind` CHECK is frozen, so this
   is a DDL step + cursor bump (schema 22).
4. **Make retries sequential, and keep the most informative failure.** One
   confirm attempt after the first fails, and a severity order
   (protocol/config evidence > transport > timeout) instead of completion order.
   Also cap total in-flight at `concurrency`, not `concurrency × attempts`.
5. **Two targets, succeed on either.** `gstatic` + one more 204/HEAD endpoint
   (or the exit-IP lookup itself). Turns 4.4 and 4.5 from an unknown into a
   known: a proxy that carries one of two targets is working.
6. **Count servers, not links.** Fill `latency_ip` on every real success
   (10 of 14 today) and report distinct exit IPs; dedupe the "7 working" claim
   against feed duplication (four links, one server).
7. **Calibrate against an oracle on samples.** Run the pinned cores
   (`crates/leas-oracles`) on 200 random links per bucket and compare verdicts.
   Without this, "7 working" is a statement about our client, not about the
   servers — the one claim the DB cannot settle by itself.
8. **A staged status, not a boolean.** The columns already carry the ladder —
   `latency_fast_delay` (transport came up), `latency_auth` (server accepted the
   config), `latency_real_delay` (target carried) — but the UI reduces it to
   `error`. A four-state display (dead / unreachable-from-here /
   config-valid-egress-broken / working) is derivable today with no schema
   change and would have shown the 111 auth-ok links as partial credit.
9. **Put the policy boundary where it already is: ingestion.** Two classes are
   distinct and must not be mixed.
   *Not a config* → hard drop at ingest, in `validate_ss_config`
   (`crates/leas-config/src/import_export.rs:157-185`), which already drops a
   malformed 2022 key, `ss none` on a cleartext wire and `mode=quic`. Add one
   rule there: the method must be one the native codec can resolve
   (`SsMethod::from_method`), case-insensitive and trimmed. `leas-proto` should
   own that list (it already owns `ss_method_support.rs`) so the parser, the
   ingest gate and the codec read one set; the parser itself stays permissive,
   as the plugin/multi-user design requires. Effect here: the 58 `null:null`
   links vanish, and with them the 9 endpoints that exist only for them.
   *Insecure* → only with the evidence reason 2 demands, and then through the
   existing machinery: `parsing.reject_insecure` for new imports (today it
   covers `insecure=1` only) and the existing per-row verdicts for stored rows
   (`config_invalid` / `not_tls`, then Purgatory's 7-day TTL) — no new schema
   value and no silent code deletion. **No row in the §3.2 inventory qualifies
   today**, and upstream removal alone never will — the flow class was
   investigated for exactly this and fails the bar (§3.3), and the corpus has no
   live instance to prove it either (§3.4).
   The rule also says what to keep, and it is checked against all three oracles:
   the ws/gRPC/HTTPUpgrade transports xray only warns about (64 043 links here),
   the SS stream ciphers sing-box still serves, the non-vision VLESS flows and
   legacy VMess ciphers sing-box/mihomo still accept, and the `quic` transport
   sing-box still ships. None is "legacy cleanup" — dropping any would trade a
   live peer for a smaller file, which is exactly what the rule forbids.

## 6. What this evidence cannot decide

- **Whether the 63 697 dial failures are dead or filtered.** One vantage, one
  budget, one concurrency setting. Recommendation 1 is the experiment.
- **Whether the 23 778 target timeouts are slow exits or broken tunnels.**
  Sample sizes are too small (14 successes) to infer a latency distribution for
  the population.
- **Whether the client is faithful on any specific bucket.** The oracle sample
  (recommendation 7) is the only external check; note that 83 rows with
  `expected Handshake record` and 491 with `0x48` (an HTTP `H`) are shapes worth
  putting in that sample first.
- **Whether a server implementing XTLS direct exists anywhere.** §3.4 dialled
  every instance this corpus has — none is alive, and 27 of the 29 were not
  dialable as XTLS at all (no TLS layer). That answers the question for this DB,
  not for the internet: an old server outside these feeds could still speak it.
- **Per-minute throughput.** `updated_at` is the write-behind flush stamp: one
  minute holds 68 099 of the 120 405 rows (29 133 of them `real`-kind), so the
  timestamps record transactions, not probes.

## 7. Reproduction

The DB was read read-only with the turso CLI (production engine, not
`sqlite3`). The live file is written by the running app, so the numbers above
came from a copy of the three files:

```
mkdir -p /tmp/leas-snap
cp ~/.config/leas/data.db ~/.config/leas/data.db-wal ~/.config/leas/data.db-shm /tmp/leas-snap/
~/.turso/tursodb --readonly /tmp/leas-snap/data.db "<query>"
```

The funnel ladder (`CASE` order is the precedence; changing it changes the
table):

```sql
WITH b AS (
  SELECT s.*, CASE
    WHEN s.error IS NULL AND s.error_kind IS NULL THEN '00 never probed'
    WHEN s.error_text LIKE 'not testable by the native engine%' THEN '01 untestable'
    WHEN s.error_kind = 'fast' AND (s.error_text LIKE '%lookup address%'
                                    OR s.error_text LIKE '%Name or service not known%') THEN '02 dns'
    WHEN s.error_kind = 'fast' AND s.error_text LIKE '%timeout on probe transport%' THEN '03 tcp timeout'
    WHEN s.error_kind = 'fast' THEN '04 tcp refused'
    WHEN s.error_text LIKE '%timeout on probe attempt%' THEN '05 target timeout'
    WHEN s.error_text LIKE '%REALITY: received real certificate%' THEN '06 reality fallback'
    WHEN s.error_text LIKE '%CertNotValidForName%' OR s.error_text LIKE '%CertificateExpired%'
         OR s.error_text LIKE '%certificate%' THEN '07 certificate'
    WHEN s.error_text LIKE '%handshake error: alert%' THEN '08 tls alert'
    WHEN s.error_text LIKE '%HTTP error%' OR s.error_text LIKE '%expected 200%'
         OR s.error_text LIKE '%expected 101, got%' THEN '09 http status'
    WHEN s.error_text LIKE 'invalid or unsupported config%' THEN '10 config defect'
    WHEN s.error_text LIKE '%vless response%' OR s.error_text LIKE '%Handshake record%'
         OR s.error_text LIKE '%early eof%' OR s.error_text LIKE '%tunnel closed%' THEN '11 framing'
    ELSE '12 other' END AS bucket
  FROM profile_stats s)
SELECT bucket, COUNT(*) links, COUNT(DISTINCT endpoint_id) eps,
       SUM(CASE WHEN purge_reason IS NOT NULL THEN 1 ELSE 0 END) purged
FROM b GROUP BY bucket ORDER BY bucket;
```

Alive count: `SELECT band, COUNT(*), SUM(rank_alive) FROM endpoint_rank GROUP BY band;`
→ `0 | 7 | 7`, `1 | 58 004 | 0`, `2 | 7 147 | 0`.

## 8. Limits of this evidence

- Settings are what `config.json` held at snapshot time, not what the run
  started with; the DB does not stamp probe parameters.
- `error_text` is capped and can be localized, so the bucket ladder is a
  best-effort classifier over prose; 1 358 rows land in "other" and 876
  endpoints are only reachable through it.
- One vantage (this host), one run. Nothing here is a claim about the servers
  themselves, only about what this client measured from here on 2026-11-19.
- The ~20–30 resolutions per manual DNS retry is the user's observation, not a
  stored metric: the retry logs `DNS retry: N endpoint(s) dispatched`, not how
  many of the N resolved, so the yield per run cannot be reconstructed from the
  DB after the fact.
- A row can keep an untestable marker through a full run: the fast dial gates
  the real phase, and the capability gate only runs in the real phase, so 490
  rows still carry a marker text the shipped binary cannot emit (§3.2 row 1).
  `updated_at` is therefore not evidence that a gate or a probe ran.
