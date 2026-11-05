# Design: Transport deltas — WS early data, mKCP masks, xhttp knobs, gRPC multi-stream, socket options

- **Date:** 2026-11-05
- **Status:** **draft — awaiting approval.** Read-only audit; no code touched.
- **Kind:** spec
- **Owners:** `crates/leas-native/src/transport/{ws,kcp,xhttp,grpc,http}/**`, `crates/leas-native/src/conn.rs` (new), `crates/leas-native/src/inbound/**` (accept-proxy only), `crates/leas-native/Cargo.toml` (socket2)
- **Evidence base:** `thirdparty/ferrox` @ `188d80d`, source-only (see the protocol spec's §0 for the method). Xray/sing-box semantics checked against `thirdparty/Xray-core` and `thirdparty/sing-box`.

## 1. Witness verdicts

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| T1 | leas **documents** WS early data as supported and does not implement it | **CONFIRMED — the comment is false** | `crates/leas-native/src/transport/v2ray/ws.rs:14-19` states "Our own ws transport supports early data". `crates/leas-native/src/transport/ws.rs:29-46` (`ws_request`) sets only `Host`, config headers, `Connection`, `Upgrade` — no `Sec-WebSocket-Protocol` anywhere in the crate (repo grep: zero hits outside that comment and its own negative test). The proto parses and round-trips the knob: `crates/leas-proto/src/proto_spec/common.rs:245`, wire codec `:949`. Xray's client puts the URL-safe base64 of the first bytes into `Sec-WebSocket-Protocol` and the server echoes it: `thirdparty/Xray-core/transport/internet/websocket/dialer.go:143-145`, `hub.go:55-59`. Ferrox implements both directions: `crates/ferrox-app/src/ws.rs:938-978` (client), `:811-853` (server echo). |
| T2 | leas mKCP has no UDP mask layer and ignores two capacity knobs the proto carries | **CONFIRMED** | `crates/leas-native/src/transport/kcp/mod.rs:52-58` builds `KcpSettings` from `mtu`/`tti` only. `upland_capacity`/`downlink_capacity` exist on the proto (`proto_spec/common.rs:313-314`, codec `:741-742`) and are never read. No mask/obfs code in `transport/kcp/**`. Xray 26 exposes `finalmask.udp` masks (`mkcp-legacy` dns/dtls/srtp/utp/wechat/wireguard, `original` FNV cascade, `aes128gcm`); ferrox ports them at `crates/ferrox-core/src/kcp/mask.rs:34-64` (masks), `:277-390` (per-connection counters), with a differential oracle `kcp/oracle.rs:92-96` driving pinned Go. |
| T3 | xhttp padding is a static `'X'` run and the range is inclusive | **CONFIRMED — both are wire-visible** | `crates/leas-native/src/transport/xhttp.rs:39-44`: `static X_PAD: [u8; PAD_MAX] = [b'X'; PAD_MAX]`, sliced 100..=1000. Xray draws the length half-open (`RandBetween`, `transport/internet/splithttp/xpadding.go:491-496`) over a **token-ish alphabet** (150-step character set, tolerance 2 on the Huffman-length check — ferrox reproduces it at `xhttp.rs:1529-1573`). A thousand identical bytes is a stronger signature than the length. |
| T4 | xhttp POST sizing is fixed, not per-POST random | **CONFIRMED** | `xhttp.rs:33` `const MAX_POST_BYTES: usize = 1_000_000` used as the cap for every POST; Xray draws a random size per POST bounded by `scMaxEachPostBytes` (`Xray-core/transport/internet/splithttp/dialer.go:472-487`; ferrox `xhttp.rs:533-535`). |
| T5 | gRPC is single-stream only | **CONFIRMED** | `crates/leas-native/src/transport/grpc.rs:1-3` "Single bidirectional stream (gun mode)". No `TunMulti`, no keepalive ping. Xray and sing-box both use `/Tun` (single) and `/TunMulti`; ferrox implements multi with `MultiHunk` grouping sized to the peer window (`crates/ferrox-app/src/grpc.rs:1622-1684`, `1086-1126`). |
| T6 | leas's HTTP/2 profile table never reaches the h2 client, and its header table has no production consumer at all | **CONFIRMED, corrected from the first pass** | `leas_tls::Http2Profile` *is* used — by the REALITY spider (`crates/leas-tls/src/reality/spider.rs:30-58`) and by `crates/leas-native/src/headers.rs:174-178` — but the product h2 client runs hyper defaults (`transport/http/conn.rs:36-54`, `h2::handshake` with no settings), and `headers.rs` is imported by **no** module in `leas-native/src` (repo grep: `use crate::headers` → zero; its only consumer is `examples/amiabot_sweep.rs`). Ferrox's h2 is hand-rolled and also fingerprint-blind on the client (`xhttp_h2.rs:1838-1843` advertises no `SETTINGS_HEADER_TABLE_SIZE`), so this is a shared gap, not a ferrox advantage. |
| T7 | leas applies no socket options to outbound dials | **CONFIRMED** | No `setsockopt`/`socket2` anywhere in `leas-native`/`leas-tls`; `socket2` is not a direct dependency of any crate. Ferrox applies `SO_MARK`, `SO_BINDTODEVICE`, `TCP_FASTOPEN_CONNECT`, `TCP_CONGESTION`, `TCP_WINDOW_CLAMP`, `TCP_USER_TIMEOUT`, `TCP_MAXSEG`, `IP_TRANSPARENT` on every dial (`crates/ferrox-app/src/sockopt.rs:449-520`, applied at `proxy.rs:1205-1211`) — real syscalls, verified by reading the call sites. |

## 2. Defects and gaps, ranked

| Rank | Item | Consequence | Class |
|---|---|---|---|
| 1 | **WS early data missing while documented** (T1) | `?ed=2048` is the most common Xray share-link shape. Without it every connect pays a full upgrade round trip *after* TLS, and the comment tells future readers the work is done. | interop + latency + false documentation |
| 2 | **No mKCP mask layer** (T2) | Xray 26 servers configured with `finalmask.udp` (or the older `seed`+obfs spellings) are unreachable; our KCP frames are identifiable as KCP. | interop + fingerprint |
| 3 | **Static `'X'` xhttp padding, fixed POST size** (T3, T4) | Both are passive-observable and both are cheap to fix. | fingerprint |
| 4 | **Single-stream gRPC** (T5) | Xray servers accept both; multi-stream is a throughput/concurrency property, not a compatibility one. Lower priority than it looks. | throughput |
| 5 | **No socket options** (T7) | Cannot bind an outbound to an interface or mark it for policy routing — the classic "the VPN eats its own dial" loop. | operability |
| 6 | **h2 client ignores the profile; `headers.rs` is unreachable** (T6) | Two tables of browser truth exist and neither reaches the wire on the h2 path. Dead weight today. | debt |

## 3. Errata — ferrox behaviours NOT to copy

| Item | Evidence | Why not |
|---|---|---|
| gRPC server never sends trailers | `ferrox-app/src/grpc.rs:1987-1989` — stream ends `DATA\|END_STREAM` with an empty body, no `grpc-status` | Stock gRPC clients never see a status. Ferrox↔ferrox passes because its client also ignores trailers (`:381-417`). |
| Literal-only HPACK encoder, hardcoded 4096 table, no `SETTINGS_HEADER_TABLE_SIZE` | `h2.rs:145-156`, `196-207` | Legal but a fingerprint and growth regression; we keep `h2`/hyper. |
| h2 leniency: even-sid HEADERS ignored, stale CONTINUATION dropped, PUSH_PROMISE ignored, padded-DATA silently truncated | `xhttp_h2.rs:2862`, `2885`, `1735`, `2744` | Each one is a protocol violation accepted silently. |
| WS server accepts unmasked frames, ignores RSV, returns EOF instead of close 1002 | `ws.rs:367`, `395`, `467` | tungstenite already gets this right on our side. |
| `User-Agent: firefox\|safari\|edge` accepted, Chrome header set emitted anyway | `headers.rs:2-9`, `62-70` | A selector that selects nothing is worse than no selector. |
| Reserved session id `"__none__"` for sessionless downlinks | `xhttp.rs:2545-2550` | A peer-chosen id can collide with it. Use an out-of-band sentinel. |
| Inclusive `xPaddingBytes` top, fixed-size POSTs | `xhttp.rs:1566-1573`, `533-535` | Copy Xray's half-open `RandBetween` and per-POST draw, not these. |

## 4. Decisions

- **D1 — implement WS early data (both the knob and the honesty).** Client: buffer up to `max_early_data` bytes of the *first* protocol write, base64url-encode them into `Sec-WebSocket-Protocol`, send them as the first binary frame after the 101, and feed the echoed header as the read prefix. Guard: only when the config sets the knob; `?ed=` remains a query flag so a non-upgraded server still works. The false comment in `transport/v2ray/ws.rs:14-19` is fixed in the same commit.
- **D2 — mKCP masks: adopt `original` + `mkcp-legacy`, reject the rest for now.** `aes128gcm`/`salamander` on top of KCP duplicate the SS/Hysteria obfs we already own, and no share link in our corpus uses them; `original` + the legacy families are what `seed`-based deployments carry. The two capacity knobs are wired as they are the only KCP tuning the proto exposes.
- **D3 — xhttp padding: half-open range over a token alphabet, per-POST random size.** The static `'X'` slice exists to keep byte length equal to HPACK-Huffman length (see its comment); the replacement must keep that invariant, i.e. the alphabet is restricted to characters whose Huffman code is 8 bits (`X`, `Z`, and the rest of the set ferrox derives at `xhttp.rs:1529-1556`).
- **D4 — gRPC multi-stream is deferred behind a measured need.** `/Tun` is what both cores use for the ordinary case; `TunMulti` changes client-side buffering and grouping for throughput we have not measured as short. Recorded so the "why single-stream" answer is a file, not folklore.
- **D5 — the h2 client adopts the profile SETTINGS, or the header table is deleted.** `Http2Profile::settings()` already exists and is already trusted by the spider; feeding it to the h2 client's `handshake` replaces hyper's defaults with the browser's table for the same `(browser, os, device)` the TLS identity resolved to. `crates/leas-native/src/headers.rs` has **no production consumer** and must either be reached from the ws/httpupgrade/xhttp request builders (its stated purpose) or deleted — a second uncompiled truth is the one outcome that is not allowed.
- **D6 — socket options land in two steps, because of `#![forbid(unsafe_code)]`.** Step 1 (this spec): `socket2` as a direct dependency for the surface it exposes safely — `TCP_USER_TIMEOUT`, keepalive, `SO_REUSEPORT`, `IPV6_V6ONLY`, `TCP_NODELAY`, `TOS`. Step 2 (**ADR required**): `SO_MARK`, `SO_BINDTODEVICE`, `TCP_CONGESTION`, `TCP_FASTOPEN_CONNECT` are not in `socket2`'s safe API and need either a documented `unsafe` exception in a new `leas-sockopt` crate or a decision to not support policy-routing marks at all. The spec does not pre-empt that ADR.

## 5. Slices

| Slice | Change | Gate |
|---|---|---|
| **S1** | WS early data (D1) + comment fix | Unit: request carries `Sec-WebSocket-Protocol` only when configured; byte-identical to Xray's encoding (base64url, no padding). e2e vs a real xray-core server with `?ed=2048`; assert the first app payload arrives inside the upgrade, not as a second write. |
| **S2** | xhttp padding alphabet + half-open range + per-POST size (D3) | Pure-function rows for the alphabet/Huffman invariant and the half-open bound; a golden POST-size distribution is *not* a test (non-deterministic), so pin the bound and the RNG draw count instead. |
| **S3** | mKCP masks `original` + `mkcp-legacy` + capacity wiring (D2) | Go-oracle style: fixed seed+conv+payload → expected obfuscated bytes, plus a round-trip. The existing KCP e2e rows must stay green. |
| **S4** | socket2 layer, safe surface only (D6 step 1) | Dial-path unit: requested options reach `socket2` (injectable seam), unconfigured dials unchanged. No syscall assertions in CI (they are not portable); the option values are asserted at the seam. |
| **S5** | `Http2Profile` consumer or deletion (D5) | Whichever branch is chosen: no dead table left behind. A consumer slice needs a byte-level SETTINGS assertion against the profile. |

## 6. Non-goals

- **Any server role** (ws/xhttp/grpc/httpupgrade inbounds). Ferrox's server halves are where most of its bugs live (gRPC trailers, h2 leniency, SS2022 UDP misrouting); leas is a client.
- **Hand-rolled HPACK or a hand-rolled h2 stack.** We keep `h2`/hyper.
- **xhttp over HTTP/3 (ferrox lacks it, we have it)**, `downloadSettings` dialing, and the `h2` PING keepalive — already documented deferrals in `docs/reference/native-core.md`.
- **xmux connection pooling.** Ferrox's pool (`xmux.rs:12-215`) is a real H2-connection pool keyed by dest+TLS identity, but Xray's `xmux` is a *mux.cool* knob set; adopting ferrox's meaning would silently redefine the config field. Deferred until our mux story is settled.

## 7. Verification plan

- S1's acceptance is behavioural on a real server (the payload must ride the upgrade), because a fake we wrote would agree with our own framing.
- S3's mask bytes come from the pinned Go implementation, never from our own encoder.
- S2's and S4's rows assert bounds and plumbing, not randomness.
