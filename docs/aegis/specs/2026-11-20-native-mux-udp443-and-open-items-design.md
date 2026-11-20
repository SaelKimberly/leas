# Native mux UDP under the `udp443` flow, and the open items — Design Spec

Date: 2026-11-20
Status: **implemented 2026-11-20** — D1-D6 landed; evidence per item below.
Origin: verification of two external reviews against `06e6929` (oracle, suite and
GitHub-Actions runs listed in §1), and
[`docs/architecture/native-core-integration.md:62-69`](../../architecture/native-core-integration.md)
(items 1-6). Repo-face, CI-timeout and doc items (S1-S5 of that report) are
deliberately out of scope here.

Owners touched: `leas-native` (`protocol/vless`, `mux_pool`, `inbound`),
`leas-oracles` (cases + config), `docs/architecture/native-core-integration.md`.
No schema, no proto, no DB.

Evidence basis and limits, stated once: one clean linux x64 host, rustc 1.100.0,
cores pinned at xray 26.11.9 / sing-box 1.15.0-alpha.13 / mihomo 1.19.33. The
oracle evidence below is 27 executed rows out of 109 in `tests/vless.rs` (the 14
`reality_wrong`/`vision_udp443` rows, then the 13 rows whose name contains
`udp`). The full oracle binary and the full default-member suite were **not**
run. Every code pointer was read, none was modified.

---

## 1. Why this exists

The review that prompted this spec reported seven red oracle rows. Re-running the
same row set at the current tip gives **two**:

| Rows run | Green | Red |
| --- | --- | --- |
| 12 × `reality_wrong_pbk`/`reality_wrong_sid` (tcp, ws, grpc × both cores) | 12 | 0 |
| 11 × other `udp`-named rows (raw, packetaddr, xudp tls, xudp reality, sbox smux) | 11 | 0 |
| 2 × `case_37_vision_udp443` (xray, sing-box) | 0 | 2 |

(That table is the PRE-fix measurement. After D1 the row is green on both cores
and the suite is 103/103 — §3 Outcome.)

So the review's REALITY claim does not reproduce under the same pins, and one
claim does: the `xtls-rprx-vision-udp443` mux-UDP row is red on **both** cores,
5 attempts out of 5, with one datagram sent, none returned
(`pooled udp sent 1 replies 0 accepted 1`). It is the only reproducible oracle
regression in the tree, and no automated job runs it.

At the same time `native-core-integration.md` still lists six open items, one of
which (`proxy UDP leg is missing`) is contradicted by rows that pass today (§5).

## 2. Scope

**In:** D1 root-cause and fix for `case_37_vision_udp443`; D2 the open-proxy
bind; D3-D5 the UDP and HTTP-CONNECT items, each with a build/record decision;
D6 converting the two unbounded items into recorded non-goals.

**Out:** everything else the reviews raised (master fast-forward, `stable-drift`
registration, `cmake` docs, CI timeouts, a scheduled oracle tier), the
subprocess cores' UDP/routing surface, DNS/TUN behaviour, and any protocol
wire change.

## 3. D1 — `case_37_vision_udp443` is red on both cores

Measured (this run): `crates/leas-oracles/tests/vless.rs:172-181`, driven through
`run_against` → `e2e_support::probe_pooled_socks_udp` (`e2e_support.rs:215`), a
real `Socks5Inbound` with `MuxPolicy::production()`, a counting proxy in front
of the core, and `UDP_PROBE_COUNT` datagrams to the UDP echo.

Bisect, all measured:

| Row | Carrier flow | App / mode | Mux | Result |
| --- | --- | --- | --- | --- |
| `case_35_xudp_tls` | none | UDP / XUDP | yes | green, both cores |
| `case_36_xudp_reality` | none | UDP / XUDP | yes | green, both cores |
| `case_37_vision_udp443` | `xtls-rprx-vision-udp443` | UDP / XUDP | yes | **red, both cores** |

The only differing axis is the flow, and its wire form is documented as
identical: the client truncates `xtls-rprx-vision-udp443` to `xtls-rprx-vision`
in the addon (`protocol/vless/header.rs:37-44`, pinned by
`:222-226`), the server config emits the truncated name and asserts it for both
cores (`e2e/config.rs:1690-1726`). What differs is **client-side composition**:
with a flow set, `connect_udp` routes to `connect_mux` over a carrier the Vision
codec wraps (`protocol/vless/mod.rs:267-300`, `:179-212`) instead of a plain
carrier.

Hypotheses, ordered by what the evidence can distinguish:

- **H1 (carrier framing).** A flow row does not merely change the addon: it
  changes the composition. `connect_mux_plain` sends `CMD_MUX` and a bare mux
  frame stream (`protocol/vless/mod.rs:400-418`); a flow row runs
  `connect_mux_vision` (`:433-469`), which sends `CMD_MUX` + the flow addon +
  the camouflage frame, peels the response header, and wraps the whole mux
  frame stream in `VisionStream`. Every mux frame — the `New` frame and every
  XUDP session packet — then travels length-prefixed inside a padded,
  TLS-lookalike record, with padding applied per record when the policy asks
  for it. That record shape, not the addon bytes, is what xray's and sing-box's
  XUDP-under-XRV readers must accept; inspect it first.
- **H2 (pool identity).** `MuxKey` includes `flow` (`mux_pool.rs:161-208`) but
  `MuxPolicy` keeps flow rows off mux unless the row spells it
  (`mux_pool.rs:103-118`); the udp443 row forces mux by a second rule
  (`e2e/case.rs:459-470`, `protocol/vless/mod.rs:271-274`). A carrier built under
  one rule and looked up under the other would reuse a pooled carrier whose
  policy (padding on/off) differs.
- **H3 (param handoff).** The inbound's proxy outbound deliberately does not set
  `params.udp` (`inbound/outbound.rs:61-72`); the ASSOCIATE path fills it
  elsewhere. If that fill drops the flow-driven mux rewrite, the session opens
  as a raw UDP tunnel on a Vision carrier.

**The one experiment** (not run here; it decides the branch) is a flow on/off
A/B on exactly the mux+UDP shape, because the flow switches the composition
above: run `case_35_xudp_tls` with `.with_flow(Flow::Vision)` added, and
compare against the already-green no-flow row.

- red ⇒ H1/H2: the padded-record mux carrier is what the servers reject. The
  udp443 name is a red herring (the addon is truncated to the same
  `xtls-rprx-vision` bytes either way).
- green ⇒ composition is fine and the defect is the udp443 rewrite itself (H3)
  or the pool key built for that flow (H2).

Then, only if red: run the same row with the pool disabled (a second carrier per
leg) to separate H1 from H2; and compare a padded vs unpadded policy
(`with_mux_padding`) to confirm the per-record padding is the trigger rather
than the codec wrapping at all.

**Outcome (2026-11-20).** The experiment was run: a `Flow::Vision` row on the
identical mux+UDP shape is GREEN on both cores (`case_37_xudp_vision`), so the
padded-record carrier is not the defect — H1 is dead. The cause was H2 plus
D3's stale item, together:

- `mux_pool::effective_mux` returned **false** for a flow row with no spelled
  `mux` (the TCP rule), while `connect_udp` forces the mux tunnel for the
  udp443 flow. The inbound therefore built a per-association raw leg for a
  config whose protocol phase only speaks XUDP.
- That raw leg then died anyway, because `proxy_params` never carried
  `params.udp` (the "proxy UDP leg is missing" item).

Fix: one predicate, `protocol::vless::udp_uses_mux`, read by `connect_udp` and
by the new `mux_pool::effective_udp_mux` the inbound's pooling decision uses;
`inbound::outbound::proxy_udp_params` now sets the mode, and the leg upgrades it
to `XUdp` exactly when it pools (a mismatched mode is refused by `connect_mux`,
not silently dropped). Evidence: `case_38_vision_udp443` GREEN on xray 26.11.9
and sing-box 1.15.0-alpha.13 (was 5/5 red), `case_35`/`case_36`/`case_37`
unchanged, `leas-native` 852/852.

The pre-fix decision rule stands as a rule, not as this row's outcome: a red
row is retired only with upstream evidence (ADR 0018).

**Unresolved contradiction to settle first.** The tree states both that xray
rejects TCP mux under XRV (`mux_pool.rs:103-105`) and that it accepts
`RequestCommandMux` under XRV (`protocol/vless/mod.rs:428-431`). One of the two
is stale. Until it is settled, a TCP-mux-under-Vision row is not a usable
experiment (a red there is either the client or the server policy); the UDP
cell is, and it is now green.

**Decision rule, per `AGENTS.md`.** If the experiment shows the client is right
and the *expectation* is wrong (a pinned server that cannot serve XUDP under
XTVISION), retire the row with the upstream quote and move the claim to a
hermetic test. Evidence rule: a peer's refusal is not enough
([ADR 0018](../adr/0018-deprecation-grounds.md)).

**Acceptance.**

1. `cargo nextest run -p leas-oracles --test vless -E 'test(vision_udp443)'` is
   green on both cores — or the row is retired with the upstream evidence in
   its reason.
2. The whole `--test vless` binary is green (109 rows).
3. Whichever row discriminated the axis stays in the suite as the regression
   guard (the flow × mux × UDP cell currently has exactly one member).
4. `just quality-gate code` green; `just hotpath` unchanged if the fix touches
   the Vision or mux write path.

**Risk.** The likely fix sits on the hot path (Vision frame assembly, mux
write). Allocation counts are pinned by `leas-hotpath`; a fix that adds a
buffer per frame must be rejected or re-pinned deliberately.

## 4. D2 — A non-loopback bind is an open proxy (build now)

Truth today: the native inbound has no authentication, and a non-loopback
`inbound.listen` only warns (`server/mod.rs:94-99`, `inbound/mod.rs:288-303`,
`inbound/http.rs:72`). A warning does not stop `0.0.0.0` from being published.

**Decision:** fail closed. `listen` outside loopback requires an explicit opt-in
(`inbound.allow_non_loopback`, default `false`, `leas-config`
`InboundConfig`), otherwise `start` returns a config error **before** `bind`.
The warning stays, but only on the opted-in path.

**Rejected alternative:** SOCKS5 RFC 1929 + HTTP Basic credentials. That is the
feature a shared LAN inbound needs, but it is not the security fix: a credential
list with no password management story is a worse default than a refusal.
Deferred until someone needs a shared bind.

**Acceptance:** a test that a non-loopback bind without the flag errors and
binds nothing (assert no listener is reachable), and that the flagged path
binds and logs once.

**Implemented 2026-11-20:** `InboundConfig::allow_non_loopback` (serde default
`false`), `ServerConfig::allow_non_loopback`, the refusal in
`NativeCoreServer::start`, and the app wiring in `ops::connect`.
`server::tests::non_loopback_bind_is_refused_without_the_opt_in` pins both
halves.

## 5. D3 — "Proxy UDP leg is missing" is stale; re-verify before building

Open item 1 says a native session drops SOCKS5 UDP ASSOCIATE through the proxy
outbound because `proxy_params` never sets `params.udp`
(`inbound/outbound.rs:61-72`). But `probe_pooled_socks_udp` drives exactly that
shape — real SOCKS inbound → proxy outbound → core — and `case_35`/`case_36`
pass on both cores.

So the item is either (a) narrowed to a path the oracle does not drive, or
(b) stale. **Decision:** re-read the ASSOCIATE path end to end and either
correct `native-core-integration.md` or fix the narrow path; do not implement
"the proxy UDP leg" from the doc as written.

**Acceptance:** the doc statement matches the code, and a green oracle row (the
pooled one already exists) is cited in the same sentence.

**Outcome 2026-11-20:** both (a) and (b). The `udp` mode really was never set
(`proxy_udp_params` now sets it), and the doc item was mis-scoped: the pooled
carrier is what every e2e row drove, so the missing leg was invisible there.
The rewritten item names the destination lock instead of a missing leg.

## 6. D4 — UDP association trace rows (build after D5)

Item 2: relayed associations carry no trace rows or byte accounting, so the
activity/sniffer views show TCP only. The relay loop must count datagrams per
association and emit the same `TraceEvent` shape TCP does.

**Acceptance:** a UDP association appears in the activity panes with
sent/received byte counts, pinned by a unit test on the relay loop; no
allocation per datagram beyond the frame itself (the loop already owns its
buffers).

**Implemented 2026-11-20:** the relay opens one `TraceKind::UdpAssoc` row on
its first forwarded datagram and closes it with the association's totals
(`Telemetry::closed_precounted` — the per-datagram `udp_sent`/`udp_received`
calls remain the host accounting, so the close does not fold them twice). The
proxy leg, which previously counted replies and drops only, now counts uplink
too. Pinned by
`inbound::tests::a_udp_association_writes_one_activity_row_with_its_totals`.

## 7. D5 — HTTP CONNECT tier-3 row (cheap, after the oracle tier exists)

Item 3: the HTTP CONNECT surface (status codes, auth gate, 16 KiB head cap,
pipelined-byte replay) is tier-1 only (`inbound/http.rs`). One `leas-oracles`
row against a real core closes it.

**Acceptance:** green through the real `HttpInbound` on both cores.

**Implemented 2026-11-20:** `e2e_support::probe_http_connect`,
`e2e::run_http_against`, and `vless_http_connect_against_cores`. Measured green
on xray 26.11.9 and sing-box 1.15.0-alpha.13. The auth-gate branch stays tier-1
and is recorded as the remaining open item.

## 8. D6 — Turn the last two items into recorded non-goals

Items 5 (SS2022 multi-user EIH) and 6 (native sys metrics are process-level
approximations) have no consumer and no owner. A perpetually open list reads as
a promise nobody scheduled.

**Decision:** move both to a "Non-goals (revisit on demand)" section of
`native-core-integration.md`, each with the trigger that would reopen it (a
server that needs multi-user EIH; a statistics field the native core can
actually observe). Items 1-4 stay as work, rewritten per D3-D5.

**Implemented 2026-11-20:** `native-core-integration.md` now has three open
items (UDP destination lock, HTTP auth gate, SS2022 EIH) and a non-goals section
(inbound credentials, richer sys metrics).

## 9. Corrections to the review record (documentation, no code)

Kept here so the next reader does not re-investigate them:

| Review claim | Corrected state |
| --- | --- |
| 5 REALITY negative rows red on xray | All 12 `reality_wrong_*` rows pass on both cores at the same xray pin |
| Two tests hang deterministically (>420 s) | `mvcc_conflict_replays_without_losing_update` 0.225 s isolated / 0.306 s under full-crate load; `batch_completion_sweeps_stale_error_markers` 2.664 s isolated / 0.526 s under load. Not reproduced; CI green on the same commit |
| `leas-tls` suite not load-stable | 297/297 pass, including both named flaky tests (0.027 s, 0.070 s) |
| 202 markdown files | 206 tracked `.md` |

Those three were environment artifacts of a loaded sandbox, not code findings.

## 10. Verification plan

```sh
just quality-gate code
cargo nextest run -p leas-oracles --test vless                 # 109 rows, real cores
cargo nextest run -p leas-oracles --test vless -E 'test(vision_udp443)'
```

The oracle commands are **manual by construction** until the project grows a
scheduled oracle tier: no gate recipe runs them (`justfile:127`), so the fix
must be re-run by hand on any change to `mux_pool`, the Vision codec, or
`connect_udp`. That cost is the reason a green row here is worth more than a
unit test: the tier is the only thing that can see this class of defect.

Measured at close (2026-11-20): `just quality-gate-ci code` green (fmt, clippy,
**2 874** tests); the whole `--test vless` binary **103 passed, 10 skipped**
(the skipped ones are pre-existing `#[ignore]`s); `leas-native` **853**,
`leas-config` **238**.

Known cost recorded, not fixed here: `just oracles-check` is red at HEAD on
several pre-existing `clippy::doc_markdown` lints in `e2e/case.rs`,
`e2e/config.rs`, `e2e/variant.rs` and four test files. That recipe is in no
gate, so the dev-only crate has been drifting; clearing them is the
precondition for adding it to one.

## 11. Open questions

1. Does xray-core 26.11.9 still accept XUDP under XRV at all? The oracle comment
   claims yes ("final-review fix wave"), and sing-box fails identically, which
   points at the client — but the experiment in §3 is what settles it.
2. Should a flow row be allowed to select mux without an explicit `muxtype`?
   `mux_pool.rs:103-118` says no for TCP; the udp443 rule says yes for UDP.
   Two rules, one behaviour: worth one owner if D1's cause turns out to be H2.
