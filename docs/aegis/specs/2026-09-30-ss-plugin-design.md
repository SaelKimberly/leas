# Shadowsocks SIP003 plugins (`v2ray-plugin`, `obfs-local`) — Design Spec

Date: `2026-09-30`
Status: `approved (rev. 14) — plan: docs/aegis/plans/2026-09-30-ss-plugin.md`
Scope: `xray-tui-proto`, `xray-tui-native`, `xray-tui-core`, `xray-tui`, docs
Related: `NATIVE_CORE.md` (Shadowsocks capability table + the `obfs plugins (SS)` deferral row), `AGENTS.md` decisions 2, 4, 11, 20, `docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md`

> **Superseded in part (2026-11-06):** `specs/2026-11-06-shadowsocks-coverage-design.md`
> replaces §3.5's `cert`/`certRaw` treatment and the §8 verdicts for `tls=<value>`,
> `cert`/`certRaw` and `mode=quic` (quic rows are now rejected at import; `tls` is
> presence-only; the cert is an SPKI pin). Plan T22's "could not be pinned" stop reason
> is moot — its source is vendored — but its conclusion stands on a stronger ground.
> Nothing else in this document is re-opened.

**Revision note.** Rev. 1 specified a narrowing typed struct against an assumed single
spelling. Review against the repo's own captured feeds (`tests/fixtures/m1n1-5ub-*.txt`)
found **seven wire shapes built from four parse mechanisms**, one of which has no `plugin=`
parameter at all and therefore already imports as a plugin-less row that dials the bare
server. Rev. 2 keeps the typed stored struct (user decision) but makes it **lossless**,
splits refusal into parse (never) and connect (always), and pins every shape to an
explicit rule. A third pass corrected the base64-JSON evidence to the one well-formed site
and dispositioned the two nested-`ss://` rows explicitly (§2.7).

**Third pass.** Review found the stored type was **not total** (a `kcptun` row fit no
variant, so it would have panicked or been silently misfiled as obfs), the ALPN default
contradicted the reference, and — the one that mattered — the batch's fast level is
protocol-kind-blind, which would have made `mode=quic` **untestable by construction**
(§8.1, now in scope, with acceptance rows 10–12).

**Fourth pass.** Review caught the one error that would have shipped a broken `wss` row:
the stream-shape diagram had TLS **inside** the ws framing. Both references put TLS
**outermost** (v2ray-core wraps the raw dialer, then upgrades; sing-box wraps the dialer,
then upgrades), which is also our chain's existing order — so the "skip `security::wrap`
for plugin rows" mechanism is deleted, `wss` reuses `security::wrap` + `WebPkiVerifier`,
and the plugin row's job shrinks to supplying *policy* through `LinkContext`. The ALPN
default is corrected with it: both references send `http/1.1`.

**Fifth pass.** Review fixed the fast-level fix's *placement* (not the plan-time gate —
`ping.rs:1745-1748` forbids it; the batch's per-`ProtocolId` config cache makes the
retirement check a cache hit), named the two edits §5 item 3 actually requires so deleting
one cannot yield a **plaintext** ws upgrade, made `tls` total and boolean-aware like `mux`
(`"tls":false` must not read as TLS on), aligned the §8 REALITY rationale with the new
mechanism, and added the missing acceptance rows 10–14.

**Sixth pass.** Review caught one more wrong seam (§5 item 4: `is_self_contained` is
xhttp-keyed, so a plugin-QUIC SS row would TCP-dial a UDP port — the fix belongs on
`protocol::is_quic_link`/`connect_quic`, which is also where the SS codec has to run over
the QUIC stream); narrowed §5 item 3 to exactly two edits (`SsConfig::security()` already
returns `Some` unconditionally, so `wrap` falls through to its `None` arm); decided the
fate of the sibling `SsConfig.plugin` field (removed — `PluginSpec` is the sole owner, with
the 7 call sites listed); and stated the 3b trust arrangement, including the negative row
that proves verification is real.

**Seventh and eighth passes.** Review found a second SNI reader outside `LinkContext` —
`extract_sni` (`ops/enrich.rs:25-33`), whose two branches both read `None` for a TLS plugin
row with an empty `security`, so the `🏳️` whitelist verdict would rest on no SNI while the
engine handshakes with a name. The **user decision: follow sing-box** then fixed the rule
itself, and it is not what either reference does alone — sing-box uses the plugin `host` as
the SNI *only when the key is present* (`sip003/v2ray.go:48-51`) and the SS **endpoint host**
otherwise (`:59`), while `cloudfront.com` is the ws `Host` header default and never an SNI
(v2ray-plugin differs: it would send `cloudfront.com`). §5.1 now owns that three-term
precedence, materializes the plugin-host term at the row-build owner (whole `security.tls`
variant, explicit `fp`/`insecure` preserved), and keeps the endpoint term out of the stored
config — decision 11(f) forbids an endpoint-derived identity — which forces exactly one
reader change, the enrichment path's endpoint fallback. Also added §3.2 rule 5 (options with
no name — the form's independent optionals and a Clash YAML with only `plugin-opts`) so it
can never fall through to a plugin-less bare dial. Acceptance rows 16–19.

**Ninth pass.** Review killed rev. 8's row-build SNI materialization on two independent
grounds — decision 11(f) (an endpoint-derived SNI would make the uid endpoint-dependent) and
the export round trip (`reconstruct_proto` emits no security for SS, `from_clash` hardcodes
`SecurityConfig::default()`, so a materialized `security.tls` would make Ctrl+E create a
second `Protocol` row for the same server). §5.1 is now one resolver in the proto crate with
two callers and nothing written to storage; `host` is exempted from identity elision because
its presence gates the SNI; reconstruction must re-derive typed fields into the opts string;
tier 3a lost its unrunnable "vice versa"; and the `needs_tls` gate keeps a plain-ws row from
being handed a real handshake. Acceptance rows 16–21.

**Tenth pass.** Review caught that "plugin + UDP" could not live in §8's `capability` list at
all: a plugin row is not untestable (its TCP path is the feature), no probe runs the UDP
carrier, and RFC 1928 gives a client no channel to report a failure after ASSOCIATE — so the
refusal would have been invisible on a row that looks green. §8's *Runtime-scoped refusals*
group now separates runtime-scoped refusals (a typed `NativeError` at the owning path, with
the honest observable behavior stated) from marker-producing config refusals, and requires
one `warn!` per association so the drop is diagnosable. Acceptance rows 22–23.

**Eleventh pass.** Review found rev. 10's mux placement was wrong twice, and the second half
is a pre-existing product bug rather than a plugin gap. `transport::upgrade` returns a
`BoxStream`, so a multiplexer cannot come from there — mux is the **protocol phase's** return
type (`protocol::connect_mux -> MuxClient<BoxStream>`, template `vless::connect_mux`), and the
SS codec runs per `open_session` (§5.2, §7). And the app never reaches mux at all: `dial`
calls `crate::connect` unconditionally, `proxy_params` leaves `params.mux` false under a
pinning test, `NativeConnectParams::mux` is documented as UDP-only, and `connect_mux`'s only
non-test caller is the e2e harness — so a VLESS `mux` feed row already **silently loses
multiplexing** in production today (it still connects: VLESS mux is client-elected and the
xray/sing-box servers auto-detect the prefix). Since `mux=1` is v2ray-plugin's server
**default** and its server *mandates* mux, refusing it would reject most real rows; §5.2
therefore makes the reachability fix required. The user then chose the **generic** branch (one
predicate for both families, VLESS TCP mux included). Scope grows to `inbound/outbound.rs` and
the probe entry. Acceptance rows 24–25.

**Twelfth pass.** Review supplied the asymmetry that reframes the whole mux item: VLESS mux is
**client-elected** (command `0x03`; xray/sing-box auto-detect the prefix), so a VLESS `mux` row
connects today and merely *loses multiplexing* — while v2ray-plugin's server **mandates** mux
(`mux.Server.Dispatch` parses frames unconditionally), so a plugin `mux=1` row fails outright.
Rev. 11's "a VLESS `mux=8` row already fails in production" was therefore overstated, and it is
the wording that would have reached the release notes; it is now scoped to a restored
optimization. It also pins the SS codec's granularity — **per `open_session`**, never once
around the tunnel, because one salt/subkey/counter stream is one SS connection
(`stream.rs:84-89, 492-496`) — and the tunnel granularity: one tunnel per `dial`, one session.
The user chose the generic reachability branch, so VLESS TCP mux runs in production for the
first time, with e2e as its only evidence.

**Thirteenth pass.** Two corrections, both from evidence, and the second invalidates the cost
the generic branch was chosen on. (1) The dispatch predicate reads the **resolved** mux and
excludes `Quic` — a `mode=quic` row may store `mux=1` while resolving `Off`, and routing it to
`connect_mux` would have no stream to wrap; it is now one accessor
(`mux_active`), read by the production dispatch *and* `connect_mux`'s SS arm (row 26). (2)
`ProxyOutbound` holds no tunnel or cache, so one-tunnel-per-dial **multiplexes nothing** — every
"regains multiplexing" claim is withdrawn, including the release-note wording, and mux is now
stated as buying **wire compatibility** for plugin rows (where the server mandates it) and
mere framing for VLESS. And `VlessConfig` has **no `mux` field at all**, so the feeds' `mux=8`,
`mux=true&muxConcurrency=8` and `muxtype=smux&…` spellings are parsed and dropped today: the
VLESS half of the generic branch is a second feature (stored field, five parse forms,
identity, form, Clash, plus a refusal for smux/yamux rows), not the one-predicate change it was
described as. The branch is re-confirmed with that cost below.


## 1. Goal and scope

The native Shadowsocks client refuses every SIP003 plugin row
(`capability.rs:361-363`), so such a config is marked untestable, falls back to a
subprocess core, and — on the xray route — silently dials the bare server. This spec
adds **in-process** plugin support so a real-world subscription row connects natively,
with a browser-grade TLS on the `wss` modes, and fails with a named reason when the row
asks for something we do not implement.

In scope (v1):

| dialect | mode | notes |
| --- | --- | --- |
| `obfs-local` / `simple-obfs` | `obfs=http` | HTTP-request obfs |
| `obfs-local` / `simple-obfs` | `obfs=tls` | synthetic-TLS obfs (**not** a real handshake) |
| `v2ray-plugin` | `mode=websocket` | `mux=0` and `mux=1` both required |
| `v2ray-plugin` | `mode=websocket` + `tls` | `wss` |
| `v2ray-plugin` | `mode=quic` | QUIC transport, TLS forced by the plugin |

Non-goals (deferred, each with its own named refusal):

- the **legacy** v2ray-plugin dialect (`obfs=websocket`/`obfs-uri` as a *mode selector*) —
  its multiplex was smux, not v2ray mux, so mapping it onto `mode=websocket` would produce
  a row that fails at connect against a smux server;
- the `shadow-tls` plugin, `gost`-style plugins, and any plugin outside these two families;
- server-side plugin support (we are a client only);
- SIP003 over UDP (SIP003 has no datagram path — §2.6);
- mux for `mode=quic` (upstream never sets it: `main.go` `case "quic"` leaves `mux` at 0);
- `ss://` rows' sibling spellings on **other** protocols (real feeds also carry
  `?plugin=obfs-local;obfs=websocket…` on `trojan://`, which our Trojan parser ignores —
  out of scope, recorded so it is not mistaken for an omission).

## 2. Pinned evidence

Read from the vendored references, upstream source, and the repo's own captured feeds —
not inferred. Citations are the record.

### 2.1 sing-box integrates both plugins in-process — and is client-only

```
RegisterPlugin("v2ray-plugin", newV2RayPlugin)   thirdparty/sing-box/transport/sip003/v2ray.go:22
RegisterPlugin("obfs-local",  newObfsLocal)      thirdparty/sing-box/transport/sip003/obfs.go:18
CreatePlugin: name → constructor lookup          thirdparty/sing-box/transport/sip003/plugin.go:28-37
```

No external binary is spawned. `Plugin` is `DialContext` only (`plugin.go:15-17`), and
sing-box's SS **inbound** has no plugin field
(`thirdparty/sing-box/option/shadowsocks.go:3-15`), so sing-box can never host a plugin
**server**. xray-core has no plugin support at all (no match for `plugin_opts`,
`obfs-local`, `simple-obfs`, `v2ray-plugin` anywhere under `thirdparty/Xray-core/`).

Consequence: our `inject_singbox` is already correct; `inject_xray`'s silent drop
(`xray-tui-proto/src/proto_spec/ss.rs:445-480` never reads `self.plugin`) is a defect that
manufactures a "server is dead" verdict for a client-config problem.

### 2.2 Defaults and keys (sing-box, matching upstream v2ray-plugin)

| key | default | source |
| --- | --- | --- |
| `mode` | `websocket` | `sip003/v2ray.go:40-43` |
| `host` | `cloudfront.com` | `sip003/v2ray.go:45-48` |
| `path` | `/` | `sip003/v2ray.go:46-53` |
| `tls` | absent (off) | `sip003/v2ray.go:27-29` |
| `mux` | `1` (websocket only) | `sip003/v2ray.go:78-86` |
| `obfs` | `http` | `sip003/obfs.go:26-29` |
| `obfs-host` | absent | `sip003/obfs.go:30-32` |

`obfs-local` reads only `obfs` and `obfs-host`; it **ignores `obfs-uri`**, and the name
`simple-obfs` is not registered. Bare keys are value `1` (`args.go` `parsePluginOptions`),
which is why presence-only keys (`tls`, and a bare `obfs`) are meaningful.

### 2.3 There is no mux negotiation — mismatch is a silent hard fail

`common/mux/server.go` `Server.Dispatch` demultiplexes **only** when the dispatched
destination is `v1.mux.cool`; v2ray-plugin's server sets dokodemo's destination to that
address iff `mux != 0`, and `ServerWorker.run` then parses frames unconditionally. No
magic prefix, no sniff, no fallback.

- server `mux=1` (the default) + plain client → SS bytes parsed as frames, handshake never
  reaches ss-server;
- server `mux=0` + mux client → the SS server reads frames as a salt and dies.

`plugin_opts.mux` describes only our side, so a mismatched row fails at connect with an
otherwise-baffling error; the refusal/timeout text must say so (§8).

### 2.4 The v2ray mux frame is byte-identical to ours

`v2ray-core/common/mux/frame.go` documents and writes:

```
2B length | 2B session id | 1B status | 1B option
          | [1B network | 2B port | address]   (status = New)
2B data length | data                          (OptionData)
```

`xray-tui-native/src/protocol/vless/mux.rs:145-309` parses and writes exactly this,
port-first address, `MAX_META` cap. **Reuse, do not reimplement** (§7).

The `New` frame's **target is inert on a v2ray-plugin server**: `handleStatusNew` really
does dispatch `meta.Target`, but v2ray-plugin's server configures that outbound as
`freedom.Config{DestinationOverride: {Server: remoteAddr:remotePort}}`, which replaces
every dispatched destination. That is why mihomo writes `127.0.0.1:0` while
v2ray-plugin's own client writes `v1.mux.cool:9527` (`common/mux/client.go`
`muxCoolAddress`) — no two mainstream clients agree, and none of them is wrong.

### 2.5 `obfs=tls` is NOT a TLS handshake, and is NOT v2ray-plugin's `tls`

Two different protocols share a word; the spec names them apart forever:

- **`obfs=tls` (simple-obfs)** — `thirdparty/sing-box/transport/simple-obfs/tls.go`: a
  synthetic TLS-1.0-framed record (`22 03 01 len`) wrapping a TLS-1.2-shaped ClientHello
  whose **first extension is `session_ticket` carrying the payload** and whose
  `server_name` is the obfs host (`makeClientHelloMsg`, `tls.go:130-204`); every later
  write is `17 03 03 len data` in 16 KiB chunks (`tls.go:19-21, 99-114`); the read side
  discards **105 bytes** of the first server record and a 3-byte header per record after
  (`tls.go:59-81`). No engine, no handshake, no certificate.
- **v2ray-plugin `tls` key** — real TLS: `streamConfig.SecuritySettings = tls.Config{ServerName: host}`
  over the v2ray stream (`main.go` `generateConfig`). This is where our `xray-tui-tls`
  engine, fingerprint, and `WebPkiVerifier` apply.

`obfs=http` (`simple-obfs/http.go:26-99`): one `GET http://<host>/ HTTP/1.1` with
`Upgrade: websocket`, `Connection: Upgrade`, a 16-byte random `Sec-WebSocket-Key`,
`Content-Length` = payload length, `User-Agent: curl/7.<rand>.<rand>`, and `Host` =
`<obfs-host>[:<port unless 80>]`; the read side drops everything through the first
`\r\n\r\n` of the first server response. A disguise, not a WebSocket — and note the port
reaches the `Host` header only, exactly as `NewHTTPObfs(conn, host, port)` splits it.

`mode=websocket` (`transport/v2raywebsocket/client.go:36-74`): path is
`URLSetPath`-normalized to a leading `/` (our existing ws path canonicalization already
matches), `Host` comes from the options headers, `User-Agent` defaults to
`Go-http-client/1.1`, and **`maxEarlyData` is never set** — the plugin path constructs
`Headers` + `Path` only (`sip003/v2ray.go:71-76`), so early data must stay **off** for a
plugin ws row even though our own ws transport supports it.

Three details the *implementation* pinned that this section states only loosely, recorded
here because each is a byte-level trap:

- **Record type bytes are `0x16` and `0x17`**, i.e. decimals 22 and 23. Written as decimals
  in a constant they read as 22 = `0x16` (right) and 17 = `0x11` (**wrong**) — a record no
  TLS parser accepts. Both are spelled in hex in the code.
- **The `obfs=tls` read side follows the C server's first buffer, not the Go port's
  "discard 3 bytes per read".** §5.3 has the pinned layout: skip 105, read the 2-byte length
  there, deliver that many bytes **raw**, and only then treat each later record as
  `17 03 03` + length + payload. The Go port instead discards 105 and then a 3-byte header
  per read (`tls.go:71-81`); the C `obfs-server` — the oracle and the deployed server side —
  appends the first payload inside the first record with no header at all
  (`obfs_tls.c:337-368`). A read is also bounded to its record, so a read that would cross a
  boundary cannot make the *next* one eat payload; the remainder is buffered.
- **The synthetic ClientHello's lengths are computed, not summed.** The reference writes
  `208 + len(data) + len(server)` (`tls.go:141, 148, 170`); a hand-kept constant drifts the
  moment a byte moves, and the body here also carries the 4-byte timestamp the reference
  writes before its 28 random bytes.

### 2.6 SIP003 has no UDP path, and no plugin server exists in either core

`thirdparty/shadowsocks-rust/crates/shadowsocks/src/relay/udprelay/proxy_socket.rs:100`
— *"Plugins doesn't support UDP relay"*. Our `ss/udp.rs::connect_udp` dials the server's
UDP port directly (`udp.rs:1129-1143`), so no layer could carry obfs.

The **server** side needs no Go toolchain:
`thirdparty/shadowsocks-rust/crates/shadowsocks/src/server/server.rs:129` starts a plugin
in `PluginMode::Server`, and `plugin/ss_plugin.rs` drives it through
`SS_REMOTE_HOST/SS_REMOTE_PORT/SS_LOCAL_HOST/SS_LOCAL_PORT/SS_PLUGIN_OPTIONS` — the env
contract the Go plugins read.

### 2.7 The captured feeds: seven shapes, four parse mechanisms

`tests/fixtures/m1n1-5ub-*.txt` (36 captured subscription files, no crate test consumes
them today). Every plugin-bearing `ss://` line, and the rule it forces:

| # | spelling on the wire | site | rule |
| --- | --- | --- | --- |
| 1 | `?plugin=obfs-local;obfs-uri=/;obfs=tls;obfs-host=IsiBugSendiri` — name and opts glued in one value, `obfs-uri` present | `1:4264`, `1:7172` | split on `;`; `obfs-uri` → `extra`, preserved and ignored at runtime (§3.5) |
| 2 | `?plugin=v2ray-plugin%3Bpath%3D%2F…%3Bhost%3D…%3Btls` — same, percent-encoded | `20:8017`, `23:3870` | decode once, then as #1 |
| 3 | `?v2ray-plugin=eyJwYXRoIjoiXC8uLg…` — **query key named after the plugin, base64-encoded JSON** `{"path":"/zpziiwsyhkk","mux":true,"host":"fn600mliness016.svcline.com","mode":"websocket","tls":true}` | `20:8014` | decode base64 → JSON → flatten; today this imports **plugin-less and dials the bare server** |
| 4 | `?plugin=obfs-local;mode=websocket;mux=false` — obfs name, v2ray vocabulary, **boolean** mux | `24:7251`, `24:7405` | vocabulary selects the family (§3.3); `mux` accepts bools |
| 5 | `?plugin=simple-obfs%3Bobfs%3Dtls%3Bobfs-host%3Ddf1fab2.dl.nintendo.net%3A16569` — **`host:port`** in `obfs-host` | `21:3563` | split the port; it feeds the obfs `Host` header only |
| 6 | `?plugin=simple-obfs%3Bobfs-host%3D51.38.112.84` — no `obfs` key | `26:3466` | `obfs` defaults to `http` |
| 7 | `?plugin=obfs-local` (name only), `?plugin=obfs`, `?plugin=obfs%3Bobfs` | `20:6641`, `23:2969`, `25:1880` | name-only is fine; bare `obfs` is **not** a registered name → named refusal |

The four mechanisms: split-on-`;`, percent-decode, base64-JSON, and value normalization
(`true`/`false` → mux, `host:port` → host + port). A shape needing a fifth mechanism is
one we have not seen yet — which is why §3's rules are phrased as "what does this key
mean" rather than as per-spelling branches.

**The nested-`ss://` rows are not spellings of the plugin contract.** `23:6439` and
`24:4149` are literally `ss://Og==@ss://<b64>@<host>:995?…`, so their userinfo decode
fails **before** any plugin branch runs and the `?v2ray-plugin=` value is never examined.
They are therefore excluded from spellings #1–#7 and pinned separately (§9 row 9b): no
panic, and a named userinfo error. No recovery heuristic is added, on evidence rather
than taste: both endpoints already exist elsewhere in the corpus — `fn600mlines021:995`
clean with byte-identical options at `23:3870` (so `24:4149` is a duplicate), and
`fn600mlines024:995` clean and plugin-less in `m1n1-5ub-27` / `-32` (so `23:6439`'s only
unique content is a plugin claim we cannot confirm). A heuristic on malformed userinfo
would buy one duplicate plus one ambiguous row, at the price of a guess about which of
the two interpretations the operator meant.

## 3. Stored contract: a typed, lossless `PluginSpec`

`SsConfig` carries **one** plugin field, not two: the sibling `plugin: Option<TinyText>`
is **removed** and `PluginSpec` becomes the sole owner of the name. Today `plugin` holds the
whole glued value verbatim (`obfs-local;obfs-uri=/;obfs=tls;obfs-host=…`), so keeping it
alongside a spec that also carries `name` would store the name twice, hash it twice under
§4's write order, and leave two sources of truth for one case-insensitive match. One owner,
one write, one comparison.

**Two refinements the implementation forced, recorded as normative:**

1. `PluginMode` carries an `Unsupported(String)` variant. Without it, a mode the row *states*
   that we do not implement has nowhere to go, and the only alternatives are the two this
   spec forbids: dropping it (the key vanishes from the row) or rewriting it to a default.
   The corpus supplies the case — `obfs=websocket`, the legacy smux dialect — and reading it
   as `http` would dial a server that neither spelling describes. It is stored verbatim and
   refused by name.
2. **`family` and `mode` normalize at parse**, not at connect: a row with no vocabulary keys
   takes the family its *name* implies, and an absent mode key stores that family's default
   (`Unknown` stays `Unset` — a name we know nothing about gets no guessed mode). The reason
   is §3.1 rule 3: the canonical export **elides** a default, so a row that stored "absent"
   would re-parse as a different stored form and a different uid. The consequence is that
   `resolved_mode()` is the stored mode for every normalized row, and identity's elision
   (§4) and the export's elision (§3.1 rule 2) are the same rule applied twice.

Every site that reads or writes the old pair (mechanical, no behaviour change beyond the
new parse):

| site | today | after |
| --- | --- | --- |
| `proto_spec/ss.rs:154-174` parse | `plugin` + `plugin_opts` map | one `PluginSpec::from_query(&query)`; the glued and base64-JSON spellings resolve here (§3.2) |
| `proto_spec/ss.rs:197-211` reconstruct | emits `plugin=` + `plugin_opts=` | emits `plugin=<name>&plugin_opts=<canonical>` — the corpus's glued form re-exports **split**, on purpose: one canonical spelling out, and §3.1 rule 3's fixed point compares *specs*, not URL text |
| `proto_spec/ss.rs:242-275` Clash | two raw `String`s | spec ⇄ those two strings; the Clash shape is unchanged |
| `proto_spec/ss.rs:514-528` `inject_singbox` | copies both fields | name + the same canonical string |
| `proto_spec/ss.rs:415-418` identity | `ID_PLUGIN` + `map_str(ID_PLUGIN_OPTS)` | both writes disappear; the typed fields take `0x50`+ (§4) |
| `config/src/forms.rs:437-441, 1873-1892` | `plugin` + `plugin_opts` **form fields** | the two *inputs stay* (a user types them) and both feed `PluginSpec::from_parts(name, opts)` — the same constructor the URL parser calls, so the form is not a second dialect |
| `native/capability.rs:361-362` | `cfg.plugin.is_some() \|\| cfg.plugin_opts.is_some()` | `cfg.plugin.is_some()` on the spec, then the per-key verdicts (§8) |

`SsConfig.security()` is untouched by any of this — it already returns
`Some(&self.security)` unconditionally (`ss.rs:368-370`).

```rust
// xray-tui-proto/src/proto_spec/ss.rs
pub struct PluginSpec {
    /// The wire name, verbatim — an open string (`obfs-local`, `simple-obfs`,
    /// `obfs`, `kcptun`, …). Never normalized away, never validated away.
    pub name: TinyText,
    /// Which option vocabulary the row speaks (§3.3). `Unknown` is a real,
    /// stored state, not a parse failure: an unregistered name has no
    /// vocabulary, and pretending it is `Obfs` would misclassify it into a
    /// mode that never existed.
    pub family: PluginFamily,      // Obfs | V2Ray | Unknown
    /// `Unset` means the key was absent — a state the wire has, distinct from
    /// any value. Defaults are applied at CONNECT (§3.4), not baked in here.
    pub mode: PluginMode,          // Unset | Http | Tls | Websocket | Quic
    /// The obfs/v2ray host, verbatim — including any `:port` suffix (below).
    pub host: Option<TinyText>,
    /// The `:port` suffix of `obfs-host`, when it parsed. When it did NOT
    /// parse, the whole raw value stays in `host` and `port` is `None`, so the
    /// row stores losslessly and `capability` refuses it at connect naming
    /// the offending value. It feeds the obfs `Host` header, never the dial.
    pub port: Option<u16>,
    pub path: Option<TinyText>,
    /// The `tls` key (v2ray family only). The obfs family's TLS is `mode`, not
    /// this flag. Total for the same reason as `mux`: the base64-JSON spelling
    /// carries a real boolean, so `true`/`false` must be distinguishable from
    /// presence and from garbage.
    pub tls: TlsSetting,           // Unset | On | Off | Invalid(String)
    /// `Unset` = key absent; `Invalid(v)` = present but unparseable, kept
    /// verbatim so the connect-time refusal can name it. A total enum is what
    /// makes "never refuse at parse" implementable without a panic path.
    pub mux: MuxSetting,           // Unset | Off | On(u32) | Invalid(String)
    /// Every key the typed fields do not own, verbatim and sorted. This is what
    /// makes the stored form lossless: `obfs-uri`, unknown keys, and future
    /// upstream options all survive a store/export/re-import cycle.
    pub extra: BTreeMap<String, String>,
}

// The type is TOTAL: every combination the wire can produce is representable,
// including `Unknown` + `Unset` for a name we have no vocabulary for (`kcptun`).
// Invariant, pinned by a test: `family == Unknown` ⟺ `mode == Unset`. A row that
// speaks no known vocabulary carries no mode, and a row with a mode has a
// vocabulary. Constructing a `PluginSpec` therefore never has to panic, never
// has to drop a key, and never has to guess a family.
```

All of it is owned by one parse function (`SsConfig::plugin_spec`, or the path that builds
it) so no two sites can disagree.

**Two layers, and only one of them refuses.** The parse/store layer never refuses a key, a
name, or a spelling: `ss.rs:154` stores the `plugin` value verbatim today, and that
losslessness is existing behavior to preserve, not something a typed struct may quietly
take away. Every key lands in a typed field or in `extra`; anything unrecognized is
**preserved, not rejected**. Every verdict — "unsupported name", "unsupported mode", "this
key changes the wire and we do not implement it" — is a **connect-time** policy decision
made by `capability::ss_reason` (§8), which names the key or value that caused it. A row
this change cannot serve therefore stays importable, exportable, and correctly marked
untestable, and it is one code path in `capability` rather than two (parse + connect)
holding the same judgement.

### 3.1 Rules that make the form lossless

1. Every raw option key lands in exactly one place: a typed field **or** `extra`. Nothing
   is discarded at parse time.
2. Reconstruction (`reconstruct_proto`) emits `plugin=<name>` plus **every typed field that is
   not at its default or `Unset`**, plus every `extra` entry, so an exported URL carries the
   same information the row was imported with. `inject_singbox` renders the same content as a
   sorted `k=v;…` string. The typed fields must be *re-derived into the opts string* — the
   current implementation only echoes `plugin` and whatever map it was handed
   (`ss.rs:197-216`), which for a typed spec would export `plugin=v2ray-plugin` alone and
   silently drop `mode`/`host`/`tls`/`mux`. That failure is invisible on the corpus (every
   feed row has at least one option to echo) and visible only on a stored row whose fields are
   all defaults, which is exactly acceptance row 20.
3. **Round-trip invariant (tier-1, §9 rows 9 and 20):**
   `uid(parse(u)) == uid(parse(export(parse(u))))` for every plugin-bearing URL, **and**
   `uid(parse(export(row))) == uid(row)` for a *stored* row — including one whose typed fields
   are all defaults and one that states a `host`. The exported form re-parses to an equal
   `PluginSpec`. This is the direct answer to "re-importing the same row produces a different
   uid", on both the wire form and the stored form.
4. Clash keeps `plugin: Option<String>` / `plugin_opts: Option<String>`
   (`clash/mod.rs:160-162`); `to_clash`/`from_clash` convert the typed spec to and from
   that string, so the Clash shape does not change.

### 3.2 Option-name resolution (spellings #1, #2, #6, #7)

1. The `plugin` query value is split on `;`. The first token without `=` is the **name**;
   the remaining `k=v` tokens are options. (`args.go` treats a bare key as value `1`.)
2. A separate `plugin_opts=` query value, when present, is split the same way and
   **merged over** the glued options (explicit wins over inline, so a feed that sets both
   is deterministic).
3. When `plugin` is absent, a query key whose name matches a known plugin name and whose
   value decodes as base64 JSON is the base64-JSON spelling (spelling #3): decode, accept
   only a flat JSON object, and flatten its members — JSON booleans become `1`/`0`, and
   every other value must be a string. **A value that is not a flat object of
   string/boolean scalars is preserved, not rejected**: the raw string is kept in `extra`
   under its query key, and `capability` refuses it at connect naming that key. No spelling
   may reach the store as a plugin-*less* row — that is the one failure this whole change
   exists to remove.
4. A name that matches no known plugin is **stored losslessly** and refused at connect
   with its own reason. Refusing at import would throw away a row a future plugin
   (or `shadow-tls`) could serve; the existing untestable-marker machinery already
   reports a connect-time refusal correctly.
5. **Options with no name.** Both of our own entry points can produce them: the form reads
   `plugin` and `plugin_opts` as independent optionals (`config/src/forms.rs:1873-1892`,
   where `check_keys` permits either alone), and Clash's SS struct carries two separate
   `Option<String>`s (`clash/mod.rs:160-162`), so a YAML with only `plugin-opts` is
   representable. The name is what selects the option *vocabulary* (§3.3), so options without
   one cannot be interpreted — and guessing here is the spec's cardinal failure, because an
   absent name that falls through yields a **plugin-less row that dials the bare server**.
   The rule: the row stores as `PluginSpec { name: "", family: Unknown, mode: Unset, extra:
   <every key> }` — losslessly, no parse rejection — and `capability` refuses it at connect
   naming the missing name. An empty `plugin=` value is the same state as an absent one. The
   corpus carries no such line, which is exactly why it needs a unit test rather than a
   fixture row (§9 row 18).

### 3.3 Family selection is by vocabulary, not by name

The name says which binary the *operator* installed; the option vocabulary says what the
bytes on the wire will be. When they disagree — spelling #4, `plugin=obfs-local` with
`mode=websocket` — the **vocabulary wins**, because that row points at a v2ray-plugin
websocket server and treating it as simple-obfs would produce a request no server
answers. The mismatch is logged once, at parse, and is visible in the exported URL.

- v2ray vocabulary: `mode`, `mux`, `tls`, `path`, `host`.
- obfs vocabulary: `obfs`, `obfs-host`.
- Both present: `obfs` together with `mode` is ambiguous — the row is **stored with both
  keys intact** and refused at connect naming the two conflicting keys. Neither present:
  the family comes from the name, defaulting to obfs.

### 3.4 Field-level rules

- `mode`: `websocket` / `quic` (v2ray); `http` / `tls` (obfs). An absent key stays
  `Unset`; the family's default is applied at **connect**, not baked in at parse.
- `tls`: `tls` (bare) / `tls=1` / JSON `true` → `On`; `tls=0` / JSON `false` → `Off`;
  absent → `Unset`. Any other value is stored as `Invalid(v)` and refused at connect, never
  guessed. A bare `tls` in the **obfs** family is the obfs TLS mode, not this flag.
  This is deliberately *not* presence-only: the base64-JSON spelling carries a real boolean
  (`20:8014` has `"tls":true`), and a generator emitting `"tls":false` for the plaintext-ws
  counterpart of such a row would otherwise be read as TLS **on** — an engine handshake
  against a plaintext ws port, reported as a TLS-level failure. Two keys of one JSON object
  must not mean opposite things.
- `mux`: accepts an integer, `true` → `On(1)`, `false` → `Off` (spelling #4 and the
  base64-JSON booleans); absent stays `Unset` and resolves to `On(1)` for websocket at
  connect, and to `Off` for quic. Any other value is stored as `Invalid(v)` — **not**
  refused here — so the connect-time refusal can quote the operator's own text.
- `host` defaults to `cloudfront.com` **at connect**, for the ws / obfs **`Host` header
  only** — it is never an SNI, and a TLS-bearing row that states no `host` resolves its SNI to
  the endpoint host instead (§5.1 term 3). The obfs family has no default host. An absent key
  stays `None` in storage. **The key's presence is load-bearing** — it decides term 2 against
  term 3 of the SNI rule — so `host` is the one plugin field §4 does **not** elide, even when
  its value is the default: a row that spells `host=cloudfront.com` gets that SNI, a row that
  spells nothing gets the endpoint host, and collapsing them would silently change which name
  a server is dialed with.
- `obfs-host=host:port` splits into `host` + `port` when the suffix parses; when it does
  not, the whole raw value stays in `host` (see the struct's `port` doc). The port is used
  **only** to build the obfs `Host` header (omitted when 80), exactly as
  `NewHTTPObfs(conn, host, port)` does — it is never the dial port.
- `path` defaults to `/` at connect and goes through the same normalization the ws path
  canonicalization spec pins.

Defaults at connect, not at parse, is what keeps identity honest: the stored row records
what the feed actually said, and §4's default-elision is what makes `?plugin=v2ray-plugin`
and `?plugin=v2ray-plugin;mode=websocket` **one** protocol row rather than two.

### 3.5 Known keys that are preserved but not honoured

`obfs-uri` is the one real case: the reference **ignores** it (`sip003/obfs.go` reads only
`obfs` and `obfs-host`), so it changes nothing on the `obfs=http`/`obfs=tls` wire, and
refusing it would make a working row untestable for a key that cannot matter. It goes to
`extra`, is logged once at debug, and the row connects.

The general rule replaces rev. 1's blanket "unknown keys are refused":

- a key that **changes the wire and we do not implement it** → named refusal;
- any other unrecognised key → `extra`, preserved, ignored, logged once.

Today exactly one key falls in the first class: `cert` / `certRaw`, a **client CA pin**.
Silently ignoring a certificate pin is the one failure mode this change does not ship, so
those two are refused by name even though they are "known".

### 3.6 Why the family split is worth it

`obfs=http` and `obfs=tls` are wire-identical across simple-obfs and the legacy
v2ray-plugin, and `simple-obfs` is a real feed spelling that sing-box does not register.
Accepting both names costs nothing and serves a working row; refusing it would not.

## 4. Identity and schema impact (the data cost, stated plainly)

- `w.map_str(ID_PLUGIN_OPTS, opts)` is **removed**. The spec is written field by field
  (name, family, mode, host, port, path, tls, mux, then `extra` sorted) with local tags
  from `0x52` up (`AGENTS.md`: local tags `0x50+`, shared range `0x01..=0x42`).
- Write ORDER in `SsConfig::write_identity`: `kind` → `security` → `ID_PLUGIN` → spec
  fields → `extra` → credentials. Credentials stay on the `cred` stream; `host` and
  `path` are not credentials.
- **Default elision** (`AGENTS.md` identity rule (c)) is mandatory now that defaults resolve
  at connect: write `mode` only when it differs from the family default (`websocket` /
  `http`), `mux` only when it differs from `On(1)` for websocket (and never for quic),
  `path` only when it differs from `/`, `tls` only when it is `On` or `Invalid(v)` (`Unset`
  and `Off` are the default and elide), and `port` only when present. Stated as the rule an
  implementer can apply directly: **`Unset` and the resolved family default write identical
  bytes — that is, nothing.** So the corpus's name-only rows and its explicit-`mode=websocket`
  rows collapse to one `Protocol` row instead of two. `Invalid(v)` and `extra` are always
  written, since neither is ever a default.
- **`host` is the one exception, and it is not an oversight.** Rule (c) elides a value equal
  to the builder's default *because the two forms then behave identically*. For `host` they
  do not: the sing-box SNI rule is gated on the key's **presence** (§5.1 terms 2 and 3), so
  spelling `host=cloudfront.com` dials that SNI while spelling nothing dials the endpoint
  host. Eliding the default would merge two configs that differ on the wire and change which
  name a server is reached by. `host` is therefore **always written** when present, default
  value or not. The cost is one extra `Protocol` row for a config nobody but a
  v2ray-plugin-faithful operator writes, and it buys a correct SNI for everyone else.
- A key that moves between a typed field and `extra` changes the uid. That is acceptable
  inside a re-key; the round-trip invariant (§3.1 rule 3) is what guarantees the *same
  input* keeps the *same* uid.
- Because the identity format changed, `IDENTITY_VERSION` (`proto_spec/identity.rs`) and
  `SCHEMA_VERSION` (`xray-tui-db/src/database.rs`) both bump and the goldens in
  `identity_format_is_frozen_for_every_kind` are re-pinned. The version byte is written
  first, so this re-keys **every** protocol row.
- `SCHEMA_VERSION` 13 → 14 therefore **wipes every user's SQLite file** on first open
  (decision 4: a tag mismatch deletes the file). Accepted as the cost of the typed
  stored form, but it is a real loss of every profile, group, measurement and
  subscription state, and it must appear in the release notes, not only here.

## 5. Owner and chain integration

Owner: **`crates/xray-tui-native/src/transport/v2ray/`** (design-review decision), a
general transport reached only from SS today.

```
stream shape:  dial ──▶ [TLS, if the plugin's `tls` key says so] ──▶ plugin framing
                       (ws | http | fake-tls) ──▶ [mux, if mux>0] ──▶ SS codec
quic shape:    a fresh quinn dial replaces dial + TLS + framing entirely  (ConnectShape::Quic precedent)
```

**TLS is the OUTERMOST layer, and that is the reference's order, not ours.** v2ray-core's
websocket dialer keeps `NetDial` as a raw `DialSystem` and, when a security engine exists,
installs `NetDialTLSContext` = `NetDial` → `securityEngine.Client(conn, …)` — so gorilla's
`dialer.Dial` performs the HTTP Upgrade over an already-handshaked TLS socket
(`transport/internet/websocket/dialer.go`). sing-box is the same shape: `NewClient` wraps
the dialer with `tls.NewDialer` (`v2raywebsocket/client.go:37-42`) and only then calls
`ws.Dialer.Upgrade` (`:93`). On the wire: **TCP → TLS → HTTP Upgrade → ws frames → mux →
SS**. (Rev. 3 of this spec had this inverted; the correction removes a whole mechanism
that would have given a `wss` row two TLS layers.)

`SsConfig` carries **no transport field**, so the selector that routes an SS row into this
transport does not exist yet. The mechanism, named — and note what is *absent* from it:

1. `LinkContext::plugin_spec()` — the SS arm of the existing typed-accessor family
   (`transport_ws`, `transport_grpc`, …): returns the row's `Option<&PluginSpec>`, `None`
   for every non-SS protocol. `LinkContext` stays the one policy surface; no second
   context type.
2. `transport::upgrade(ctx, stream)` gains a plugin arm, dispatched on
   `ctx.plugin_spec().is_some()` **before** the `TransportConfig` match, because an SS row
   has no `TransportConfig` to match on. This arm is **framing only** — the ws upgrade, the
   `obfs=http` head, the synthetic-TLS records. It never applies TLS, and it does **not**
   produce the mux layer: `upgrade` returns a `BoxStream`, and a multiplexer is not a stream
   (§5.2 owns mux).
3. **No `chain.rs` change**, and exactly **two** edits. `secured_upgraded` already runs
   `security::wrap` then `transport::upgrade`, which is the reference's order, so the phase
   stays where it is and `wss` reuses `security::wrap` + `WebPkiVerifier` instead of
   growing a second TLS owner.

   The path a plugin row with an **empty** `security` takes today is worth writing out,
   because deleting the `chain.rs` line alone does **not** turn TLS on — it produces a
   silent-dial bug on the corpus's most common shape. `SsConfig::security()` returns
   `Some(&self.security)` **unconditionally** (`proto_spec/ss.rs:368-370` — and the doc
   comment there explains why the accessor must exist), so `wrap`'s first early return at
   `security/mod.rs:32` does *not* fire. Execution reaches the `is_tls()` guard at `:37` —
   which is `security().is_some_and(|s| s.tls.is_some())` (`context.rs:113-115`), false here
   — returns the stream **unwrapped**, and never reaches the `None => Ok(stream)` arm at
   `:134` either. The row then performs a **plaintext ws upgrade** against a TLS port.

   The two edits, and they are sufficient and necessary:
   - `LinkContext::is_tls()` gains `|| plugin_spec().is_some_and(needs_tls)` — true for the
     v2ray family with `tls` set, and for `mode == Quic` (which forces TLS anyway);
   - `security::wrap`'s `None` arm (`:134`) becomes "build the engine `TlsConfig` from the
     context when the plugin wants TLS", reading SNI/fingerprint/`insecure`/pin/ALPN from
     `LinkContext` exactly as the `Some(Tls)` arm does today.

   Nothing else changes: `ctx.security()` keeps its unconditional `Some`, and the
   `SecurityConfig`-shaped policy reading is reused rather than duplicated.
4. **`mode=quic` hangs off `protocol::is_quic_link`, not `is_self_contained`.** Rev. 5 named
   the wrong seam, and the wrong seam fails silently. `is_self_contained` is
   **xhttp-keyed** — `ctx.transport_type() == Some("xhttp") && http_version == "3"`
   (`transport/mod.rs:56-58`) — and its only consumer in the dial path is
   `Some("xhttp") if is_self_contained(ctx)` (`transport/mod.rs:32`). An SS row reports
   `transport_type() == None` (`context.rs:212-219`), so it can never reach that arm: it
   falls to `None => tcp::connect(...)` and **TCP-dials the server's UDP port**, failing at
   the first byte even with `is_self_contained` made plugin-aware.

   The seam that actually carries a fresh QUIC dial plus `quic_guard` placement is the
   chain's own branch: `protocol::is_quic_link(ctx)` → `protocol::connect_quic` under
   `quic_guard` (`protocol/mod.rs:76`, `chain.rs:100-107`). So plugin-QUIC is an arm beside
   that predicate (or inside it), and `connect_quic` gains the SS case: it performs the
   quinn dial with plugin-forced TLS and then runs **the SS codec over the QUIC stream** —
   `connect_quic`'s return value *is* the tunnel for every other QUIC member
   (`protocol/mod.rs:96-111`), so the SS AEAD handshake cannot be left to a later phase the
   branch `continue`s past. `mode=quic` forces TLS inside quinn (the reference does the
   same: `case "quic"` sets `*tlsEnabled = true`), so it never reaches phases 2 or 3 at all.
5. REALITY on a plugin row is refused in `capability` (§8), i.e. **before** the chain, and
   that refusal is load-bearing rather than cosmetic: with plugin awareness added to
   `is_tls()`, a plugin row carrying REALITY would otherwise be handed to the engine's
   REALITY arm (`security/mod.rs:78`) — a steal target wrapped around an obfs stream, which
   no server has. It also folds TLS and REALITY into one predicate (`context.rs:113-115`),
   so the guard cannot be expressed in the context alone.

Note what item 3 does **not** claim: it does not skip `security::wrap` for plugin rows, and
it does not give the transport a TLS owner. TLS outermost is the chain's existing order, so
the plugin's only job is to say whether the session is TLS and with what material.

TLS policy for a plugin row, read from `LinkContext` and never re-derived:

- **SNI**: resolved by one function (§5.1) — an explicit `security.tls.sni` wins; else the
  plugin's `host` when the plugin states one; else the endpoint host; else none.
  `cloudfront.com` is the ws `Host` header default, never an SNI. Nothing is written into the
  stored config, so the SNI stays a per-link fact and the export round trip keeps its uid.
  `SecurityConfig::sni()` reads `RealityOpts.sni`, which is unreachable here because REALITY
  was already refused.
- fingerprint id, `insecure`, `pin_sha256`, curves: from `security` when the row carries
  any; otherwise the engine defaults (WebPKI roots, no pin, the default fingerprint). A
  subscription row that names no fingerprint must not be given one silently — ADR 0009's
  rule is that an unhonourable request is approximated *and marked*, so the plugin path logs
  the same approximation `security::wrap` already logs.
- **ALPN: `http/1.1` by default on a TLS plugin row**, matching both references —
  v2ray-core passes `security.OptionWithALPN{ALPNs: []string{"http/1.1"}}` at the ws dial
  site, and sing-box sets `NextProtos = ["http/1.1"]` when the caller left it empty
  (`v2raywebsocket/client.go:38-40`). Rev. 3 of this spec wrongly claimed no ALPN, on the
  strength of v2ray-plugin's `tls.Config{ServerName: host}` carrying no `NextProtos` — the
  ALPN is supplied at the dial site, not in that struct. An explicit `security` ALPN wins.
- `obfs=http` and `obfs=tls` need none of this: they are a plain head and a synthetic
  record writer respectively, not TLS sessions, so a plugin row in either mode must not
  resolve to TLS at all (§8).

### 5.1 The SNI is a per-link fact — one resolver, two callers, nothing stored

**The reference rule (user decision: follow sing-box).** sing-box sets
`tlsOptions.ServerName = hostOpt` **only when the `host` option is present**
(`transport/sip003/v2ray.go:48-51`); when it is absent, `tls.NewClient(…,
serverAddr.AddrString(), tlsOptions)` uses the **SS endpoint host** (`:59`). And
`cloudfront.com` (`:45`) is the ws **`Host` header** default — it is *never* the SNI.
(v2ray-plugin differs on exactly this point: `tls.Config{ServerName: *host}` with `host`
defaulting to `cloudfront.com`, so a host-less row would get `cloudfront.com`. We follow
sing-box, and the divergence is named here rather than discovered by a failed handshake.)

**One resolver, in the proto crate, next to the config it reads:**
`plugin_sni(config: &ProtocolConfig, endpoint_host: &str) -> Option<String>`, applying

1. `security.tls.sni`, when the row states one;
2. else the plugin's `host`, **when the plugin states one** and the plugin requests TLS
   (`needs_tls`, §5 item 3);
3. else the endpoint host, for a TLS-bearing plugin row that states no `host`;
4. else `None` — every non-TLS case, `obfs=http` and `obfs=tls` included.

Two callers, one answer: `LinkContext::server_name()` (the engine) and the enrichment path
(`spawn_whitelist_pass`, which holds the endpoint and therefore can supply term 3). `None`
for the obfs modes is not a gap: those are a plain HTTP head and a synthetic record writer,
so there is no TLS session and no SNI, and inventing one from the obfs `Host` would make the
`🏳️` verdict a false statement about the row.

**Why nothing is written into the stored config.** Rev. 8 proposed materializing
`security.tls` at the row-build owner. Two independent facts kill it:

- **Decision 11(f)**: endpoints do not participate in identity, so one `Protocol` row serves
  one config across every server carrying it. Term 3 is the endpoint host, so any
  materialization of it makes the uid endpoint-dependent and splits one protocol into N rows
  — invisible to any test that loads one server per config.
- **The export and Clash round-trips do not carry security for SS.** `reconstruct_proto`
  emits only `plugin=`/`plugin_opts=` (`proto_spec/ss.rs:197-216`) and `from_clash` hardcodes
  `SecurityConfig::default()` (`ss.rs:263`); VLESS asserts its security survives its own
  round trip (`vless.rs:1027-1040`), so SS is the outlier, not a choice. A materialized
  `security.tls` would make `uid(parse(export(row))) != uid(row)` — the shipped Ctrl+E export
  path would silently create a **second `Protocol` row for the same server**, which is
  exactly the fixed point §3.1 rule 3 asserts. Aligning SS export with VLESS is a real change
  and belongs in its own spec, not inside this one.

So `SsConfig::security()` keeps returning the row's own (possibly empty) security, the
`security.sni` column keeps meaning *the SNI the row states* and nothing more, and §5 item
3's two context edits are **necessary** — not a second line of defense. `extract_sni`
(`ops/enrich.rs:25-37`) therefore stays as it is for the stated case; the plugin case is
answered by the resolver at its call site, and the one honest consequence is recorded: for a
host-less TLS plugin row the column is `None` while the engine dials the endpoint host, and
the `🏳️` verdict uses the resolver's answer rather than the column.

### 5.2 Mux is a protocol-phase return type — and the app path never reaches it

Rev. 10 put "the mux session pool" in the transport arm. That is wrong twice, and both halves
are load-bearing for `mux=1`, which is v2ray-plugin's server **default** and the corpus's
dominant shape (`20:8014`, `"mux":true`).

**Wrong seam.** `transport::upgrade` returns `Result<BoxStream, NativeError>`
(`transport/mod.rs:63-75`); a multiplexer is not a byte stream, so it cannot be produced
there. The codebase already models this correctly: mux is the **protocol phase's** return
type — `protocol::connect_mux(ctx, stream) -> MuxClient<BoxStream>` (`protocol/mod.rs:349-362`),
reached through `connect_chain_mux`, whose own doc says the last link "runs the mux protocol
phase and the result is the MuxClient multiplexer instead of a byte tunnel"
(`chain.rs:190-193`). `vless::connect_mux` (`vless/mod.rs:335`) is the template. So plugin-mux
is an **arm of `protocol::connect_mux`**: it returns a `MuxClient` over the framed stream, and
the SS codec runs the AEAD **per `open_session`**, mirroring VLESS. `transport/v2ray` stays
framing-only, and §7's frame codec is shared, unchanged.

**The codec is per session, and the natural mistake here is silently fatal.**
`ss::stream::connect` draws a **fresh random salt per connection** and derives
`subkey = stream_subkey(method, key, salt)` into a fresh `SsStream`
(`protocol/ss/stream.rs:492-496`), and the file states the invariant in its own words: the two
directions share nothing but the cipher, "that independence is the protocol's replay defence,
so a salt/counter is never carried across" (`stream.rs:84-89`). One salt/subkey/counter stream
is therefore exactly one SS connection. So the mapping is:
`SsStream<SessionStream>` — **instantiated per `open_session`**, never once around the mux
tunnel. One codec shared across sessions would push two connections' bytes through a single
counter stream, which the server's per-connection subkey rejects and which also breaks chunk
framing — on the exact row shape the corpus carries.

**Tunnel granularity — and the honest word for what mux buys here.** `outbound::dial` runs once
per app connection, and `ProxyOutbound` holds only `protocol`, `server` and `resolved_ip`
(`inbound/outbound.rs:44-50`) — no tunnel, no cache. So the mapping available today is **one
mux tunnel per dial carrying exactly one session**, and that is what the spec specifies: the
server builds a `ServerWorker` per inbound stream (`common/mux/server.go`), so a fresh tunnel
per dial is correct and stateless.

But follow that to its end, because it changes what the feature is: **one session per tunnel
multiplexes nothing.** Every app connection still pays TCP + TLS + upgrade + a mux `New` frame
+ one session, which is *more* bytes on the wire than today's plain stream. So:

- For a **plugin** row this is exactly right, because the server **mandates** mux (§2.3):
  mux here buys **wire compatibility**, not multiplexing. That is the whole requirement, and
  one-tunnel-per-dial satisfies it completely.
- For a **VLESS** row it would buy nothing but overhead, because VLESS mux is client-elected
  and xray/sing-box auto-detect the prefix. Real multiplexing needs a **pooled per-proxy
  tunnel** — one tunnel, a session per app connection, with lifetime and eviction rules — and
  that is a separate feature, not this one.

Every "regains multiplexing" claim this spec previously made is therefore withdrawn, including
the release-note wording. What a VLESS row would get under a generic predicate is a
mux-framed single stream: compatible, and slightly more expensive.

**Wrong reachability — and this one is a pre-existing product bug, not a plugin gap.**
`protocol::connect_mux` is **VLESS-only today**: every other protocol returns
`NotImplemented("mux protocol connect (native mux path is vless-only)")`
(`protocol/mod.rs:360-362`). And the app never asks for mux at all:

- `inbound/outbound.rs:64-75` dials `crate::connect(proxy_params(proxy, target))`
  **unconditionally** for `OutboundKind::Proxy` — `connect_chain` has no mux branch;
- `proxy_params` leaves `params.mux` at its default and a test **pins** that
  (`outbound.rs:263-265`: *"proxy_params builds a TCP link; the UDP relay sets its own
  mode"*, `assert!(!params.mux)`);
- `NativeConnectParams::mux` is documented as UDP-only — *"Mux tunnel for **UDP** … Ignored by
  the TCP path (`crate::connect`)"* (`context.rs:37-42`) — and the only production reader is
  the UDP path (`vless/udp.rs:246-259`);
- `connect_mux`'s only non-test caller is the e2e harness (`e2e/harness.rs:806`).

So today a **VLESS `mux=8` row from a real feed does not multiplex in the app** — and it does
not even reach the point where that could matter, because `VlessConfig` has **no `mux` field at
all** (zero matches for `mux` in `proto_spec/vless.rs`): the `mux=8`, `mux=true&muxConcurrency=8`
and `muxtype=smux&muxmaxc=4&mux=4&…` spellings the feeds carry are parsed and **dropped**. The
row still connects, because VLESS mux is client-elected (command `0x03`, `vless/udp.rs:246-251`)
and the xray/sing-box servers auto-detect the prefix rather than requiring it. What is missing
is an optimization, not a connection — and the hard-failure case remains the v2ray-plugin one
below, where the same reachability gap makes the row fail outright (`probe.rs:91` →
`crate::connect`).

**Why not refuse it instead.** The two cases are not symmetric, which is the whole point:
VLESS mux is *elected by the client* (so a server that tolerates plain streams keeps working),
while v2ray-plugin's server sets dokodemo's destination to `v1.mux.cool` whenever
`mux != 0` and `mux.Server.Dispatch` then parses the stream as frames **unconditionally**
(§2.3) — the client cannot elect out. A named refusal of `mux>0` would therefore reject the
shape v2ray-plugin's servers produce **by default** (`20:8014` carries `"mux":true`), gutting
the corpus coverage the accepted matrix demands. The reachability fix is required, and the one
branch that changes a shipped protocol's behavior — whether it also switches VLESS on — was put
to the user.

**The dispatch predicate is stated once, resolved, and read from both sites.** The stored
`MuxSetting` is not the predicate: a `mode=quic` row may *store* `mux=1` while **resolving** to
`Off` (§3.4, matching both references — `case "quic"` never sets mux, and v2ray-plugin sets
`connectionReuse` only for websocket, §2.2). A predicate reading the stored value would route
such a row to `connect_mux`, which has **no stream to wrap** — `mode=quic` replaces dial +
security + framing with the quinn dial (§5 item 4) — so it would fail in the app while its e2e
row passed. So:

> `mux_active(link) == resolved_mode.is_stream() && resolved_mux.is_active()`

as **one accessor** in the proto crate next to the spec it reads. The production dispatch
(`outbound::dial`, the probe entry) and `protocol::connect_mux`'s SS arm both call it, so the
stored-vs-resolved distinction cannot be re-derived differently at the two sites. `Quic` never
qualifies, whatever the stored key says.

**Activity, never magnitude — pinned before any VLESS `mux` field exists.** `is_active()` is
true for an absent key (the family default), for any positive cap, and for **unlimited**
(`mux=-1` / `muxConcurrency=-1`; the *unlimited* value is what a cap must be able to hold).
A magnitude test (`> 0`) is the trap:
`-1` is not representable in the `u32` a plugin cap uses, so an unlimited row would resolve
mux-**off** and dial without frames — the same silent-wrong-answer class as the
`connect()`-bypasses-mux defect the 3b and 3a rows caught. The stored VLESS cap is therefore a
**variant** (`Limited(u32) | Unlimited | Invalid { key, value }`), never a number, and what
identity records is the request **with its value**, not bare presence. *(Amended 2026-09-30:
this originally said "presence, not magnitude". Presence-only merging is a decision 11(d)
collision — `cap:8` / `cap:unlimited` / `cap:0` / `invalid:{key}={value}` are four stored states
that each re-import to themselves, and because the refusal verdict reads the stored field, an
`Invalid` row sharing a uid with a plain row makes the marker land on the **plain** row. An
absent mux is the only state that writes nothing.)* Row 25's VLESS case uses the `-1` spelling
so the guard is covered by the case that exists for it.

1. `params.mux` is set from that accessor for **both** families, and its doc comment stops
   claiming the TCP path ignores it.
2. `outbound::dial` (plus the probe entry) dispatch on it: mux active → `connect_mux` →
   `open_session` per connection; otherwise today's `crate::connect`.
3. `protocol::connect_mux` gains the SS arm (§5.2's codec-granularity rules apply verbatim);
   `MuxClient`'s API is reused as-is.
4. `proxy_params`' test is updated to the new contract rather than deleted.

**The VLESS half, itemized (user decision: full VLESS mux in this change).** `VlessConfig` has
no `mux` field today — the feeds' spellings are parsed and dropped — so this is a feature, not a
predicate, and it is written out as tasks:

5. **Stored field.** `VlessConfig.mux: Option<VlessMux>` — the *presence* is the decision
   (absent = no mux, which is today's behavior), and the value is the concurrency cap the feeds
   carry (`8`, `true` → the reference default, `-1` = unlimited). `muxConcurrency` /
   `muxmaxc` are read as that cap; `muxConcurrency=-1` is
   unlimited, not a parse error.
6. **Parse.** At least these corpus spellings, all verified present in
   `tests/fixtures/m1n1-5ub-*.txt`: `mux=8` (`13:5855`, `15:6208`),
   `mux=true&muxConcurrency=8` (`14:946`, `18:7707`), lowercase `muxconcurrency=8` (`18:7717`),
   and hiddify's compound `muxtype=smux&muxmaxc=4&mux=4&muxsmax=0&muxpad=False` (`6:277`,
   `15:6680`, `33:5087`). Keys are matched case-insensitively, as the rest of the query parser
   already does.
7. **A named refusal for the other multiplexers.** `muxtype=smux` (and `yamux`, `h2mux`) select
   a *different* multiplexer that the `mux.cool` codec in §7 cannot speak. Those rows are
   refused **by name** — never handed mux.cool frames, which would fail against a smux server
   with a framing error rather than a config reason. The refusal lives in `capability`, so the
   row keeps the `[untestable]` marker and stays purge-safe (§8).
8. **Identity.** One new local tag, written **only when the field is present** — presence is
   load-bearing here exactly as `host` is for the plugin SNI (§4), so there is no elision
   against a default. Existing non-mux rows therefore keep their exact identity bytes; the
   §4 re-key still applies to everything, as it does for the plugin field.
9. **Form + Clash.** A `mux` field in the VLESS form; Clash's VLESS `mux` is a **bool**:
   `true` → `Limited(8)` (the reference cap), `false` → `Limited(0)` — a **stated "no"**,
   NOT an absent key, mirroring the plugin family's `MuxSetting::Off`. A row that says "no"
   and a row that says nothing are different stored rows (and dial identically); collapsing
   them would make row 31's round trip lossy in a way the spec elsewhere forbids. Converted
   both ways.
10. **The pooled tunnel is explicitly still out of scope.** VLESS gets a mux-framed single
    stream in this change; connection reuse — the part that makes it an optimization — is a
    follow-up with its own lifetime/eviction rules. The release note says so in those words.

The narrower alternative is recorded rather than dropped: **plugin-only**, filing the VLESS
feature above as its own change. It was the recommendation *before* the two corrections in the
thirteenth pass (the stored-vs-resolved predicate, and `VlessConfig` having no `mux` field at
all) were established; the user chose to absorb the work here rather than split it.

Cost, stated: the change now spans `xray-tui-proto` (the plugin spec, the `VlessConfig.mux`
field, five parse forms, two identity writes), `xray-tui-native` (`transport/v2ray`,
`transport/mux` extraction, `protocol::connect_mux`'s SS arm, `context::is_tls`/`server_name`,
`ss::udp`, `inbound/outbound.rs`, the probe entry), `xray-tui-core` (the injectors) and
`xray-tui` (the form field, the batch's fast-level fix). The release notes must say, in these
words:

- *"Shadowsocks SIP003 plugin rows (`v2ray-plugin`, `obfs-local`) now connect natively"*;
- *"VLESS profiles that request mux are now sent over a mux-framed connection — one session per
  connection, no connection reuse yet"* — **not** a restored optimization and **not** a bug fix:
  the row connected before and still connects, it simply gains framing, and the reuse that would
  make it cheaper is a follow-up;
- *"the stored database is recreated on first launch"* (the §4 schema wipe), which is the one
  user-visible cost in the release.

The three behavior changes are independent enough to bisect separately: the plugin feature
(where mux is a hard compatibility requirement), VLESS mux framing, and the stored-schema
reset.

## 6. Mode contracts

| mode | read side | write side | engine TLS | notes |
| --- | --- | --- | --- | --- |
| `obfs=http` | drop through the first `\r\n\r\n` of the first response | one `GET` head, then raw | no | `Host` carries `:port` unless 80; `obfs-uri` preserved, unused |
| `obfs=tls` | skip 105 bytes, read the 2-byte length **there**, deliver that many bytes **raw** (the first buffer carries no record header), then one `17 03 03`-headed record at a time: 3-byte header, 2-byte length, at most that many payload bytes (§5.3) | synthetic hello (payload in `session_ticket`, `server_name` = obfs host), header order `type(1) + length(3) + version(2)`, then `17 03 03 len` records ≤ 16 KiB | no | record types are `0x16`/`0x17` (decimals 22/23); the length fields are 2 bytes, so an unframable chunk is an **I/O error, never a truncated record**; reads are record-bounded |
| `mode=websocket` | ws frames | ws frames, `Host` header, UA `Go-http-client/1.1`, early data **off** | only with `tls` | 101 required; path normalized to a leading `/` |
| `mode=websocket` + `tls` | as above, **inside** TLS (TLS outermost, §5) | as above, inside TLS | yes, by the chain's security phase | engine + `WebPkiVerifier`, SNI per §5, ALPN `http/1.1` unless `security` sets one |
| `mode=quic` | QUIC stream | QUIC stream, then the **SS AEAD codec on that stream** inside `connect_quic` — the branch `continue`s past every later phase, so the codec cannot be deferred to one | yes (forced, quinn-internal) | mux unsupported; §5 item 4, §10 open item |

## 7. Mux: extract, never duplicate

The v2ray mux codec moves out of `protocol/vless/mux.rs` into a shared owner
(`transport/mux/`) with the session logic; `protocol/vless` and `protocol::connect_mux`'s SS
arm both call it. The existing vless mux tests move with it and stay the codec's pin, so
vless behavior cannot change as a side effect — its e2e rows and goldens are the guard. The
**owner of the mux layer is the protocol phase, not the transport** (§5.2): `transport/v2ray`
frames the stream, and `protocol::connect_mux` wraps it in a `MuxClient` whose sessions each
carry the SS AEAD codec.

**The dummy target.** The `New` frame carries a destination that a v2ray-plugin server
overrides with its `freedom.DestinationOverride` (§2.4), and mainstream clients disagree
about its value. This spec writes **`v1.mux.cool:9527`** — the value v2ray-plugin's own
client writes (`common/mux/client.go` `muxCoolAddress`), because that is the reference
implementation of the plugin we are implementing. It is a named constant with the citation
above, not an incidental literal. mihomo's `127.0.0.1:0` is the documented alternative, and
3b runs **both** (§9 rows 4 and 4b) so the choice is proven load-bearing-or-not instead of
assumed. Inbound frames carry no target requirement: the reader must not demand one.

## 8. Refusal surface (every refusal names the row's own key/value)

`capability::ss_reason` is the single owner of the **config-scoped** verdicts below — the ones
a probe can reach, each keeping the existing machinery intact: the row carries the
`[untestable]` marker (`ops/ping.rs::is_untestable_marker`), so `remove_failed_servers`
still cannot delete it (`is_removable_failure`), and a real probe records the typed reason
rather than a synthesized failure. Refusals on paths no probe runs are **not** here — they are
runtime-scoped, below.

- unregistered plugin name (e.g. `obfs`, `kcptun`), naming the name;
- unsupported mode for the family, naming mode + name;
- bad `mux` value, naming the value, and the reminder that a server-side `mux` mismatch is
  the likely cause of a connect timeout (§2.3);
- `cert` / `certRaw` — client CA pin unimplemented, never silently ignored (§3.5);
- `obfs=websocket` (the legacy smux dialect), naming the smux reason;
- mixed vocabulary (`obfs` + `mode` in one row);
- REALITY on a plugin row, refused **here, before the chain**, because §5 item 3 makes
  `is_tls()` plugin-aware: without it, a plugin row carrying REALITY would reach the
  engine's REALITY arm inside the obfs framing — a construct no server has. The context
  cannot hold the guard itself, since `is_tls()` folds TLS and REALITY into one predicate
  (`context.rs:113-115`).
- `security.tls` on an `obfs=http`/`obfs=tls` row. With TLS outermost (§5) this would be a
  real engine session wrapping the obfs framing, and the obfs server's first bytes are the
  synthetic hello it expects to parse — it would never see them. The two also answer the
  same request twice, so the row says so instead of connecting to nothing.

`inject_xray` returns `SupportError` for any row carrying a plugin: xray-core has no
SIP003 support, so the honest outcome is a build-time refusal (decision 2's rule, already
used for reality and cipher validity) instead of a config that silently dials the bare
server.

**One refusal belongs in the other group.** "plugin + UDP" (SIP003 has no datagram path, §2.6)
cannot be a `capability` refusal, because a plugin row is not untestable — its TCP path is
exactly what this feature adds, and marking the whole row untestable would disable the
feature's main benefit. It belongs to the runtime group below.

### Runtime-scoped refusals: real errors, not markers

Some combinations are refused on a path that no probe ever runs, so a `capability` reason
would be the wrong instrument — it would either not surface at all, or surface by degrading a
row that is otherwise healthy. Those refusals live with the code that owns the path, they
return a typed `NativeError`, and their observable effect must be stated honestly:

| refusal | enforced in | what the user sees |
| --- | --- | --- |
| plugin + UDP | `protocol/ss/udp.rs::connect_udp`, beside the existing `security` refusal (`udp.rs:1121-1127`) | **nothing, by protocol** — see below |

The UDP case is the one place where a refusal cannot announce itself, and saying so is the
requirement rather than an apology. RFC 1928 gives a SOCKS5 client **no channel to report a
failure after the UDP ASSOCIATE reply**: the association is established, and every later
failure is a dropped datagram that the client can only observe as a timeout. On top of that,
nothing in the probe pipeline can detect it — the fast half is a TCP connect
(`FastPingManager`) and the real half is one HTTP request over the tunnel, so a plugin row
whose TCP path works is `[fast]`- and `[real]`-green while its UDP traffic dies silently.
Worse, the inbound's UDP policy is deliberate: per-datagram failures drop the datagram and
never end the association, so the failure does not even surface as an association teardown.

The behavior is therefore: **the first UDP dial attempt returns a typed `Config` error naming
the plugin, the datagram is dropped, the association stays up, and every later datagram
fails the same way.** To keep that diagnosable rather than invisible, `connect_udp` emits
**one `warn!`** (target `xray_tui_native::protocol::ss::udp`, so it reaches the actions panel
and the log store) naming the row — protocol kind, endpoint `host:port`, plugin name and
mode — and the reason (SIP003 has no datagram path). One per association, not per datagram:
a per-datagram warn on a busy association is itself a log flood.


### 8.1 The fast level is protocol-kind-blind, and a QUIC plugin row breaks it

`FastPingManager::ping(config_type, addr, port)` picks its adapter from `ProtocolKind`
alone — `adapter_for(ProtocolKind::try_from_i32(config_type))`
(`xray-tui-core/src/ping/adapters/mod.rs:71-97`) — so an SS row always takes
`TcpPingAdapter`, and `SsConfig`'s plugin mode is not an input. For a `mode=quic` row the
server port is **UDP**: the fast probe's TCP connect is refused, `classify_fast_failure`
calls that a hard connect-class failure (`ops/ping.rs:618-621`), `stage_result` records
the link in `hard_fast` (`ops/ping.rs:2227-2234`), and `after_fast_settle` then returns
before dispatching the real half (`ops/ping.rs:1822-1825`, counted as
`skipped-unreachable`). The net effect is the worst possible one: the row shows a `[fast]`
marker, is never real-probed, and looks dead while its server is alive.

So the pipeline is in scope for this change, not a follow-up — and the placement is
constrained, so an implementer does not reach for the obvious one:

1. **Not the plan-time gate.** `dispatch_page` states the rule in the code:
   *"The kind-level testability gate: it needs only the in-memory `proto_kind`, so it is
   decided here — the one place every batch passes through. The config-aware half runs
   inside the real probe, the only place a loaded config exists"*
   (`ops/ping.rs:1745-1748`). A plugin-mode test there would need the plugin spec, which
   lives in the deferred `ProtocolConfig` JSON — unloaded on the page projection by
   decision 21 — so it would cost a config load **per planned link** on the hot path, for
   every link in the feed rather than the rare ones. The gate stays config-free.
2. **The retirement decision is the right place** — the one site that reads `hard_fast`,
   `after_fast_settle` (`ops/ping.rs:1822`), inside the range `ops/ping.rs:1807-1830`. It
   is where a hard fast failure is turned into "never real-probe this link", and it already
   sits on the rare path. Before it consults `hard_fast`, it
   resolves the link's plugin mode from the batch's **existing** `protocols` cache —
   `DashMap<ProtocolId, Arc<LoadedProtocol>>`, "Protocol rows WITH their config, loaded
   once per `ProtocolId` per batch", built to replace a 67–121 µs-per-LINK reload
   (`ops/ping.rs:858-866`). For a datagram-mode plugin row it then: does **not** insert into
   `hard_fast`; does **not** count `skipped-unreachable`; dispatches the real half; and
   **retracts the `[fast]` failure marker** the fast half just staged, because a TCP connect
   to a UDP port was never evidence about this row. On a cache miss the check loads that
   one protocol row (67–121 µs, then cached) — still bounded by the hard-failure rate, not
   by the plan size.
3. **The fast probe itself keeps running.** Skipping it would need the config at fast
   dispatch, i.e. per link, i.e. item 1's cost again. A refused TCP connect to a UDP port is
   cheap, bounded, and is withdrawn by item 2's retraction — which is why the retraction is
   part of this spec rather than an optional tidy-up.
4. `FastPingManager::capability_for` feeds the TUI's per-protocol indicator and takes a
   `config_type` int, so the same plugin-mode knowledge must reach it or the UI advertises
   a TCP fast probe for a datagram row. Prefer reading the row's own resolved mode at the
   call site over widening `xray-tui-core` with plugin vocabulary. The same accessor
   serves the single-ping menu path, which is the other consumer of this blindness.

## 9. Verification

**Tier 1 — hermetic (CI gate, no toolchain).** In-process servers speaking each mode's
framing, asserting the exact bytes we write and strip: the `obfs=http` head, the synthetic
TLS hello (including the `type(1) + length(3) + version(2)` header order `check_tls_request`
enforces at `data[9..11]`) and the pinned first-buffer layout — skip 105, read the 2-byte
length there, deliver that many bytes **raw**, then `17 03 03` records (§5.3) — the ws 101
exchange with early data off, the
mux frame round-trip through the extracted codec, and every refusal reason.

**Tier 1b — corpus test (new; no crate consumes `tests/fixtures/m1n1-5ub-*.txt` today).**
Walk every `plugin`-bearing `ss://` line in the captured feeds and assert: it parses; its
`PluginSpec` matches the §2.7 table; and `uid(parse(u)) == uid(parse(export(parse(u))))`
(§3.1 rule 3). This is the test that stops the next feed spelling from arriving as a
silent bare dial.

**Tier 3a — differential vs a second implementation (pinned binary, no new toolchain).**
One direction only, because only one direction exists: sing-box is a plugin **client**
(`Plugin` is `DialContext` only, `transport/sip003/plugin.go:15-17`, and its SS inbound has no
plugin field — §2.6), so it cannot be a server we dial. What 3a asserts is that a **real
second client emits the same framing**: the same recording peer is driven once by sing-box's
in-process `v2ray-plugin` client and once by ours, for one `mode=websocket` row, and the two
streams are compared — ws upgrade head, then frames.

**The comparison is structural, not a raw byte diff, and the reasons are concrete:**

1. **Two fields are not fixed by either implementation.** The ws `Sec-WebSocket-Key` is random
   per connection, and the mux session id is a per-connection counter. Both are masked.
2. **The mux `New`-frame target is a third value, not two — and that is expected, not a defect.**
   v2ray-plugin's own client writes `v1.mux.cool:9527` (`common/mux/client.go`); mihomo writes
   `127.0.0.1:0` as an **IPv4** literal (atyp `0x01` + four octets,
   `mihomo/transport/v2ray-plugin/mux.go:158-164`); sing-box writes `vmess.MuxDestination`
   (`thirdparty/sing-box/transport/sip003/v2ray.go:118`). **`sing-vmess` is not vendored** — a
   grep over `thirdparty/` finds only *uses* of `MuxDestination`, never its definition — so its
   bytes cannot be stated statically and are only observable at runtime. §2.4 already records
   that no two mainstream clients agree on this field and that none is wrong, and §7 pins ours
   to v2ray-plugin's own value; row 4b proved it inert. Measured on a recording peer: sing-box
   sends the **same domain** with port **666** and session id **0**, ours port 9527 and session
   id 1 — so the disagreement is the *port*, not the name. The comparator therefore treats the
   target as **masked**, and a run that observes sing-box emitting a *different* target is an
   expected result — **never** a reason to align our constant onto sing-box's. A differential
   test that tempts a deliberately-chosen constant to be changed is the one way 3a could make
   things worse.
3. **The framing is packed differently, so neither the frame count nor the frame lengths are
   comparable.** Measured on a recording peer (tier 3a's own run): ours sends `[22, 89, 6]` — a
   **payload-less** `New` (`0014 0001 01 00 01 2537 02 0b "v1.mux.cool"`: session 1, option `00`,
   TCP, port 9527), then the SS handshake in a following `Keep`/`Data` frame
   (`0004 0001 02 01 0051 …`, `data_len` 81), then a trailing `End` (`0004 0001 03 00`) that is
   only this test dropping the session. sing-box sends `[105]` — one `New` with the handshake
   **inline** (`0014 0000 01 01 01 029a 02 0b "v1.mux.cool" 0051 …`: session 0, option `01`, TCP,
   port 666, `data_len` 81). Same bytes, different boundaries, so the `option` byte differs for
   the same reason (0x00 = data follows in the next frame, 0x01 = data inline) and is dropped
   from the comparison.
   **This reason is rewritten from those captures; the earlier wording had it backwards** (it
   claimed the *reference* emitted a payload-less `New`). The comparable quantity is the
   **summed `data_len`** over frames whose option carries data — 81 on both sides — which is
   exactly the AEAD-length-preservation claim and survives both the packing difference and the
   control frames. The mirror-image temptation must be resisted too: do not "fix" our client to
   emit a data-bearing `New` so that a frame-count comparison passes. Our codec mirrors xray's
   `writeData`/`getNextFrameMeta(New)` packing and the 3b rows pass with it, so the comparator
   accommodates the reference we chose, not the other way round. The frame count itself is a
   **timing** observation — both clients stall after their first burst — so it is reported,
   never asserted.
4. **Config parity is part of the row.** sing-box defaults `host=cloudfront.com`, `path=/` and
   mux on (`sip003/v2ray.go:45-46, 100`), so both clients must be given identical `host`,
   `path` and `mux`, or the row compares two different conversations.

**The sing-box binary is operator-supplied, like 3b's plugin binaries**, through
`XRAY_TUI_CORE_BIN_DIR` (the harness skips without it). Two consequences stated so the row's
status cannot be misread: a **skip is never a green row**, and the version used must be
*reported*, not assumed — this repo's e2e harness pins sing-box 1.13.16, while an operator may
supply a different build (a 1.14.1 binary was used when this tier was first run), and the
`plugin`/`plugin_opts` fields it needs are the ones those released builds accept
(`sing-box check` on the generated config is the gate, not the version string).

A loosened-but-honest comparator that still pins the layout beats either a raw diff that cannot
pass or a row quietly dropped. A green 3a is evidence about our **framing**, never about our
client as a server, and this row is worded so it cannot later be cited as more than that.

**Tier 3b — real plugin server (required for done; opt-in for CI).** A vendored
shadowsocks-rust `ssserver` started with the plugin in `PluginMode::Server` (§2.6) plus
pinned `obfs-local` and `v2ray-plugin` release binaries in an env-gated directory
(`XRAY_TUI_PLUGIN_BIN_DIR`, mirroring `XRAY_TUI_CORE_BIN_DIR` — never a CI requirement,
hard-fail on version mismatch like the core binaries). The only layer that proves the
**server** contract, which neither core can host.

**Trust arrangement for the TLS-bearing 3b rows (5, 6).** A local `v2ray-plugin
--server;tls` serves a **self-signed** certificate — it has no ACME path on a test host —
and §8 refuses `cert`/`certRaw` precisely because we do not implement a CA pin. Left
unstated, the matrix reads as unreachable: the implementer hits the refusal and cannot
proceed. The arrangement, chosen so it contradicts nothing:

- the 3b row for a TLS mode carries `security.tls.insecure = true` (SNI still from the
  plugin host, per §5). §5 already lets `security` supply `insecure`; the SS URL parser
  never fills `security`, so a form-shaped or harness-built row is the realistic way a user
  reaches this, and the harness builds it explicitly.
- plus one **negative** row: the same wss row *without* `insecure` against the self-signed
  server must fail as a TLS **verification** error. Without it, `insecure = true` would
  prove only that the handshake runs, and a client that skipped verification entirely would
  pass rows 5 and 6 — the one thing those rows exist to rule out.

This is a test-harness trust decision, not a product one: the refusal of `cert`/`certRaw`
stands, and no shipped path gains a verification bypass.

One consequence of §5.1 to keep in the harness: rows 5/6/15 set an **explicit**
`security.tls.sni` matching the self-signed cert's name. A host-less plugin row would dial
the endpoint host instead, so row 15's verification failure would be about the wrong name —
the row would go red for a reason the test does not claim to be testing.

Acceptance matrix — every row green in its own layer before this is done:

| # | row | layer |
| --- | --- | --- |
| 1 | `obfs=http` dials the real `obfs-local` server | 3b (+1) |
| 2 | `obfs=tls` dials the real `obfs-local` server | 3b (+1) |
| 3 | `mode=websocket`, `mux=0` dials the real `v2ray-plugin` server | 3b (+1) |
| 4 | `mode=websocket`, `mux=1` (dummy target `v1.mux.cool:9527`) | 3b (+1) |
| 4b | same row with mihomo's `127.0.0.1:0` target — proves the field is inert | 3b |
| 5 | `mode=websocket` + `tls` (wss) dials the real `v2ray-plugin` server | 3b (+1) |
| 6 | `mode=quic` dials the real `v2ray-plugin` server | 3b (+1) |
| 7 | sing-box's in-process `v2ray-plugin` client and ours agree on rows 3–4 | 3a |
| 8 | every §8 refusal returns its own named reason, and no row writes a byte first | 1 |
| 9 | every **well-formed** plugin-bearing feed line parses, matches the §2.7 table, and is uid-stable through export/re-import | 1b |
| 9b | the nested-`ss://` lines (`23:6439`, `24:4149`) do not panic and yield a named userinfo error — no plugin branch runs | 1b |
| 10 | a batch containing a `mode=quic` row yields a **real** result for it: `real_calls` reached, `skipped-unreachable` did not count it, and no `[fast]` marker survives — hermetic through the `BatchProbeRunner` stub (`ops/ping.rs:713`) | 1 |
| 11 | the per-row fast indicator and the single-ping fast path report **no TCP probe** for a datagram-mode plugin row (§8.1 item 4) | 1 |
| 12 | a non-QUIC plugin row (`obfs=http`, `mode=websocket`) **still takes the fast level** and still gets a fast marker — the anti-overreach guard, since "skip fast for plugin rows" would pass row 10 while silently de-optimizing every other plugin row | 1 |
| 13 | `?plugin=v2ray-plugin` and `?plugin=v2ray-plugin;mode=websocket` share one `ProtocolId`; `mux` absent and `mux=1` likewise; `tls` absent and `tls=0` likewise (§4 default elision) | 1 |
| 14 | a `kcptun` row stores as `family: Unknown, mode: Unset` with every key intact, and is refused at connect naming the name (§3 total type) | 1 |
| 15 | the wss row **without** `insecure` against the self-signed 3b server fails as a TLS verification error — verification is real, not skipped | 3b |
| 16 | the resolver answers identically for the engine and for enrichment, on a **host-stating** TLS row (both = the plugin host) and on a **host-less** one (both = the endpoint host) — and the stored config gains **no** `security` (§5.1) | 1 |
| 17 | a **plain** `mode=websocket` row that states a `host` but no `tls` resolves to **no SNI at all** and keeps `security` empty — the `needs_tls` gate, without which a plaintext ws port would get a real handshake | 1 |
| 18 | `plugin_opts` with no `plugin` name (the form's independent optionals, or a Clash YAML with only `plugin-opts`) stores as `name: ""`, `family: Unknown`, every key intact, and is refused at connect naming the missing name — never stored as a plugin-less row (§3.2 rule 5) | 1 |
| 19 | 3b rows 5/6/15 set an explicit `security.tls.sni` matching the self-signed cert, because under §5.1 a host-less row would dial the endpoint host and fail verification for the wrong reason | 3b |
| 20 | `uid(parse(export(row))) == uid(row)` for a **stored** row: one with `family: V2Ray, mode: Websocket, host: None, tls: Unset, mux: Unset` (all defaults, so the export carries only `plugin=<name>`) and one that states a `host` — the Ctrl+E path must not create a second `Protocol` row (§3.1 rules 2–3) | 1 |
| 21 | `host` is never identity-elided: a row spelling `host=cloudfront.com` and one spelling nothing get **different** uids, because the SNI rule is presence-gated (§4) | 1 |
| 22 | a plugin row's first UDP dial returns a typed `Config` error naming the plugin, drops that datagram, keeps the association up, and emits **exactly one** `warn!` naming the row (kind, `host:port`, plugin name, mode) and the SIP003 reason — a second datagram on the same association adds no second warn (*Runtime-scoped refusals*) | 1 |
| 23 | the same plugin row's **TCP** path is unaffected by that refusal: it still dials, still probes `[fast]`/`[real]` green, and is not marked untestable — the anti-overreach guard on that group | 1 |
| 24 | the **production** path reaches mux: a link with `mux_active` dispatches `connect_mux` and opens a session per connection — asserted through `outbound::dial`, not only the e2e harness (§5.2) | 1 |
| 25 | a plugin `mux=1` row and a VLESS `mux` row both take the mux path from the app, and a non-mux row still takes `crate::connect` — the anti-overreach guard on §5.2 | 1 |
| 26 | a `mode=quic` row that **stores** `mux=1` still takes the QUIC dial and is **not** routed through `connect_mux` — the stored-vs-resolved predicate guard, since the quic path has no stream for a mux phase to wrap (§5.2) | 1 |
| 27 | the SS codec is instantiated per `open_session`, never once around the tunnel: two sessions over one `SsStream` must not share a salt/subkey/counter stream — the `stream.rs:84-89` invariant, pinned with a two-session case | 1 |
| 28 | each corpus VLESS mux spelling parses to the stored field with the right cap: `mux=8`, `mux=true&muxConcurrency=8`, lowercase `muxconcurrency=8`, `muxConcurrency=-1` (unlimited — **not** corpus-backed for VLESS: the row cited earlier, `m1n1-5ub-10.txt:2966`, is a **trojan** URL whose `mux=` is empty. No VLESS feed row carries `-1`, so the case is synthetic by construction and its test says so.) — and an absent `mux` stores absent (§5.2 item 6) | 1b |
| 29 | a `muxtype=smux`/`yamux`/`h2mux` row is refused **by name** at `capability` — never handed mux.cool frames — and keeps the `[untestable]` marker and purge safety (§5.2 item 7) | 1 |
| 30 | identity: a VLESS row with `mux` absent writes **no** mux bytes, so a pre-existing non-mux row's identity payload is byte-identical apart from the `IDENTITY_VERSION` byte; present writes exactly one tag (§5.2 item 8) | 1 |
| 31 | Clash `mux: true` ⇄ stored `Limited(8)`, `mux: false` ⇄ stored `Limited(0)` (a stated "no", NOT absent), both directions; and the VLESS form's `mux` field round-trips (§5.2 item 9) | 1 |

Rows marked `(+1)` are also covered hermetically: the 3b dial is the proof, the tier-1
test is the regression pin. A row that cannot be made green is **not** quietly dropped —
it stays in this spec with its evidence and its disposition.

## 10. Risks and open items

- **`mode=quic` is the highest-risk row.** v2ray's QUIC transport is quic-go with its own
  knobs, not stock QUIC, and the vendored reference only shows
  `transport/v2ray/quic.go`'s client constructor. Plan task: pin the client wire from
  upstream v2ray-core source before writing code, and land row 6 as its own commit.

- **The fast level's kind-blindness is a pre-existing gap this change walks into** (§8.1).
  Left alone it makes `mode=quic` untestable by construction, so the pipeline fix ships
  with the transport, not after it. A `PluginSpec`-driven capability accessor is the one
  place both the batch and the single-ping menu read, so the gap cannot reopen for a
  future UDP-carrying plugin mode.
- **The DB wipe (§4) lands with the feature.** It must be in the release notes, or a user
  discovers it by losing their feed.
- **Mux asymmetry (§2.3) is user-hostile by nature.** The connect-time error and the
  probe refusal text must state the likely cause (client/server `mux` disagreement) rather
  than a bare timeout.
- **The base64-JSON spelling (#3) is the highest-value fix in this spec**: those rows
  currently import as plugin-less and dial a bare server, which reads as "the server is
  dead" and can be purged. It is also the shape most likely to reappear in a future feed
  under a new plugin name, which is why §3.2 resolves it by *name match + decodable shape*
  rather than a hard-coded `v2ray-plugin` special case. The two nested-`ss://` rows are
  deliberately left failing (row 9b) rather than recovered — both their endpoints already
  exist in the corpus in other form (§2.7), so recovery would be a guess for no new server.
- Native becomes strictly better than the subprocess here (fingerprint-grade TLS on `wss`,
  no plugin dependency), so decision 20's native-first path now serves these rows; the
  override warning should name the plugin as the reason when an override forces a core.
- Open: whether a `wss` row with no `security.tls.sni` verifies against `obfs-host` or the
  endpoint host. Spec says `obfs-host` (it is the name the server's certificate is issued
  for); pinned by a tier-1 test and row 5.

### 5.3 The `obfs=tls` first response — offsets pinned by a probe, and exact because the structs are `packed`

The 3b row 2 hang was a framing mismatch, and the numbers that settle it are the compiler's.
A probe over the vendored `simple-obfs/src/obfs_tls.h`:

```c
sizeof(struct tls_server_hello)        = 96
sizeof(struct tls_change_cipher_spec)  =  6
sizeof(struct tls_encrypted_handshake) =  5   offsetof(len) = 3
```

Those three sizes are exact, and they are also what the field sums give, because **every one
of these structs is declared `__attribute__((packed, aligned(1)))`**
(`obfs_tls.h:47,56,62,85,116,123,130`): the `short`/`int` members sit on odd offsets
(`handshake_version` at 9, `random_unix_time` at 11) with no padding inserted. Assume ordinary
alignment instead and the arithmetic yields 100/8/6 — a payload at 114 — which is the
hypothesis that was wrong here before the probe settled it.

The C server's first buffer is `[server_hello 96][CCS 6][encrypted_handshake 5][payload]` with
the payload appended **raw** — no `17 03 03` header — and `encrypted_handshake->len` carrying
the payload length (`obfs_tls.c:337-368`). So the **payload length is at offset 105** and the
**payload starts at 107**. Only later writes go through `obfs_data` with a `tls_data_header`
(`obfs_tls.c:165, 372-375`).

Two consequences the reader must not re-derive:

- the read side parses the first buffer as *length-then-raw-payload* and only then switches
  to 5-byte record headers. The Go port instead discards 105 and reads a 3-byte header per
  read (`transport/simple-obfs/tls.go:59-81`) — which is where the inherited constant came
  from, and why the C and Go shapes disagree. The C `obfs-server` is the oracle and the
  deployed server side, so the C layout is normative here; the divergence is recorded rather
  than harmonised away.
- `FIRST_FLIGHT_SKIP` is an **offset**, not a flight size, and a test pins its value.

The **request** side was verified against the reference's own bytes rather than re-derived: the
built `obfs-local`, run in client mode against a plain listener, emits
`16 03 01 00 ec | 01 | 00 00 e8 | 03 03 …` — `type(1) + length(3) + version(2)`. An earlier
reading of this spec concluded the write side was already correct because the ticket
**offsets** matched; the field *order* did not, and the oracle proved it (§5.4). Offsets agreed
precisely because both layouts use a 6-byte header — which is why an offset comparison cannot
disprove a transposition.

### 5.4 The request-side handshake header: `type(1) + length(3) + version(2)`

The C struct declares the handshake header in that order (`obfs_tls.h:33-36`) and
`check_tls_request` enforces it: it accepts only when `data[9] == 0x03 && data[10] == 0x03`
(`obfs_tls.c:514-520`), i.e. the **version** sits at 9..11. Emitting the version *before* the
length — which is what an implementer reaches for, because that is the shape most TLS
documentation shows — fails that check, and the plugin then `disable`s **itself, silently**
(`obfs_tls.c:525-530`): both stages go to -1, `is_enable` goes false, and every byte is passed
through raw.

The symptom points at the wrong layer, which is why this belongs in the evidence section: the
plugin then hands our TLS record to the SS server as if it were the SS stream, and the far side
reports a *Shadowsocks* decrypt failure for a client that never sent Shadowsocks bytes. It was
the defect that cost the most turns in implementation, and the reference's own bytes are the
cheapest disproof of the intuitive layout: the built `obfs-local`, run in client mode against
a plain listener, emits `16 03 01 00 ec | 01 | 00 00 e8 | 03 03 …`.
