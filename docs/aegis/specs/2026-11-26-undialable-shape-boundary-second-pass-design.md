# Undialable-shape boundary, second pass — Design Spec

Date: 2026-11-26
Status: **implemented 2026-11-26** (U1/U3/U5/U6 + D2/D3; D1 stays **no**). Task order and
per-task evidence: [`plans/2026-11-26-undialable-shape-boundary-second-pass.md`](../plans/2026-11-26-undialable-shape-boundary-second-pass.md).
D2's one open check was closed during implementation: `sing-vmess/vless` `NewClient`
accepts only `""`/`xtls-rprx-vision` at the pinned module revision, so all three pins refuse
a legacy flow. D1 was resolved during this spec's evidence pass: **no** — the pins serve it.
Origin: the 2026-11-26 `[n-a]` audit of the live database (168 293 links), the tracing of
4 still-served configs to their upstream feeds, and the residual gaps left by
[`2026-11-19-probe-truth-and-ingest-boundary-design.md`](2026-11-19-probe-truth-and-ingest-boundary-design.md)
S5 (ingest gate) and S10 (marker refresh).

Owners touched: `leas-proto` (`is_undialable_shape`, `normalize_vless_encryption`, flow
normalisation), `leas-config` (ingest validators), `leas-db`
(`purge_invalid_shapes_once`, one rekey-style DATA step), `leas`
(`ui/profiles.rs` cell precedence).

Evidence basis and limits, stated once: two snapshots of the same live DB (127 MiB, taken
~1 h apart, identical marker counts), source reads at `794785b0`, one fetch of the 9
configured `groups.url` sources at 2026-11-26 15:00, a Python re-implementation of
`RankLink::key`/`representative_index` over 502 dumped links, and reads of all three
pinned cores (`Xray-core` 26.11.9, `sing-box` 1.15.0-alpha.13, `mihomo` 1.19.33) in
`thirdparty/`. Limits: the app's import ran at 06:15, so the fetch is not the snapshot
that produced the rows; 2 of 9 sources returned 429 stubs and were not fetched; feed lines
rotate, so a stored value with no current upstream line is *unverifiable*, not proven feed
junk. Nothing below is implemented; every pointer was read, none was executed.

---

## 1. Why this exists

`[n-a]` is `ui/profiles.rs::test_cell_content` (`:859`) rendering a persisted
`not testable by the native engine: <reason>` marker — `capability::support_reason`
refused the row, so no probe ran. At the snapshot: 160 marker rows, 84 already
`purge_reason='config_invalid'`, **76 live rows on 54 endpoints**. All 54 endpoints render
the badge (every marked link is its endpoint's representative; the static weight only
breaks `(bin, stab)` ties and never decides marked-vs-unmarked), so the grid shows exactly
54 `[n-a]` rows.

Live rows, by class, with the verdict this spec's evidence supports:

| rows | reason (abridged) | class after the three-core read |
| --- | --- | --- |
| 37 | `vless encryption <value> is not a VLESS encryption value` | **invalid at every pin's VLESS surface, in-tree** (xray's client takes only `""`/`none`/mlkem, sing-box has no field, mihomo's factory only `""`/`none`/mlkem) → boundary gap, **U1** |
| 13 | `legacy vmess payload security is not implemented` (`enc` `none`/`zero`) | **served by the pins** (mihomo `none`, sing-box `none`/`zero`/`aes-128-cfb`) → `[n-a]` is correct; implementing it is a feature, **not** a boundary item (D1 = no) |
| 13 | `no native implementation for this protocol kind` (wireguard 10, hysteria1 2, http 1) | correct n/a — feature gap |
| 9 | `vless flow is not implemented` (`vision-udp443-udp443` ×5, `direct-udp443` 2, `visi` 1, `origin` 1) | 5 are a **suffix-duplication artefact** mihomo already tolerates (it truncates the flow to 16 bytes) → normalise (**U6**); 4 are a retired variant → **D2** |
| 3 | `transport is not implemented` (bare `quic`) | correct n/a — xray-only transport |
| 1 | `vless multiplexer muxtype=smux` | **stale config** (row 11-12, `MuxWire::Smux` landed 11-17) |

The undialable-shape rule exists **three times**, with different coverage:

| predicate | where | covers |
| --- | --- | --- |
| parse refusal | `leas-proto` `normalize_vless_encryption` (`vless.rs:1329`), `normalize_flow` (`:279`) | junk `encryption` (ParseError), `flow=none` alias |
| ingest gate | `leas-config::import_export` `validate_ss_config:170`, `validate_vless_shape:236`, `validate_hysteria2_shape:264`, `validate_host:788` | ss method, flow-without-layer, hysteria2 obfs, host |
| stored-row step | `leas-proto::proto_spec::is_undialable_shape` (`mod.rs:29-47`) | host, ss method, flow-without-layer, hysteria2 obfs |
| capability | `leas-native::capability` `support_reason:134` | everything native cannot serve, incl. encryption and vmess `enc` |

`is_undialable_shape` lacks the encryption rule, so the 37 rows the parser now refuses and
the capability still refuses never earn `config_invalid`: they sit in the Active band and
re-earn `[n-a]` on every probe. The 2026-11-19 S5 note — "invalid values (e.g.
`aes-128-gcm`) are left in place — `capability` refuses them by name" (`rekey.rs:30-32`) —
is the design that produced them; S5's DATA step could not retire them because its
predicate does not look at encryption.

**The predicate's own contract, which this spec must not break**
(`proto_spec/mod.rs:20-30`): *"What it is NOT: a deprecation list. A variant some pinned
oracle still serves (non-vision flows over TLS, legacy SS stream ciphers, the `quic`
transport) is never 'undialable'."* The three-core read showed that sentence's examples
have each moved (U5). The principle stands, and it is what decided D1 against the first
draft of this spec: vmess `none`/`zero` is served by two pins, so it is not undialable.

## 2. Governing rule

ADR 0018 stands unchanged: a *variant* is retired only for measured absence or an
evidenced upstream finding of harm; a peer's refusal is never a ground; **invalid ≠
deprecated**; stored invalid rows take a verdict and Purgatory retires them. The split:

- **U1** is invalidity: the value is refused in-tree by all three pins (xray
  `proxy/vless/outbound/outbound.go:85` takes only `""`/`none`/mlkem; mihomo's factory only
  `""`/`none`/mlkem; sing-box has no field at all) and by our parser.
- **D1 = no.** vmess `none`/`zero` is a variant the pins still dial — mihomo by explicit
  arm, sing-box by its option enum (`zero` chosen by sing-box's own TLS path); the badge is
  honest, and the fix, if wanted, is implementing the payload cipher.
- **D2** is a genuine deprecation question: `xtls-rprx-direct`/`-origin` were a working
  variant on cores older than every pin. Ground for retiring them: no pin dials them
  (§4.4 — xray and sing-box by name, mihomo by truncate-and-compare; sing-box verified at
  its pinned `sing-vmess` revision) and no shipped codec does.

## 3. Scope

| # | Item | Class | Kind |
| --- | --- | --- | --- |
| U1 | VLESS `encryption` rule in `is_undialable_shape` | store boundary | defect fix |
| U3 | `invalid_shapes_purged` marker 3 → 4, re-run the scan once | data step | defect fix |
| U4 | Marker refresh is visited-only; record the residual, no sweep | capability | documentation |
| U5 | The predicate's doc comment names a flow example no in-tree pin serves | documentation | defect fix |
| U6 | Normalise a `xtls-rprx-vision` flow carrying repeated `-udp443` suffixes (parse + one rekey-style DATA step) | parse + data | defect fix |
| D1 | Legacy vmess payload ciphers join the boundary | policy | **decided: NO** (§4.3) |
| D2 | Non-vision flows: a deprecation list beside the boundary, never inside it | policy | **decision** |
| D3 | A purged row's cell shows the purge label, not `[n-a]` | display | **decision** + ADR 0003 amendment |

Non-goals (explicit):

- Implementing vmess `none`/`zero` payload security, wireguard, hysteria1, HTTP proxy or the
  bare `quic` transport. Those are variants the pins serve and we do not; their `[n-a]` is
  the honest statement and the work belongs to `docs/reference/native-core.md`, not here.
- Repairing stored configs beyond U6. 48 of 52 suspect configs are no longer served by any
  feed and their source lines are gone; rewriting a config we cannot re-derive would be
  invention. The one repairable row (`muxtype=smux`) is not worth a re-parse data step.
- Consolidating the four predicate owners into one module. U1 keeps its rule in `leas-proto`
  and makes the capability read it, but `leas-config`'s validators and
  `is_undialable_shape` remain parallel copies guarded by agreement tests. The real fix —
  one `undialable_reason(config) -> Option<Cow<'static, str>>` consumed by the parser, the
  gate, the store step and the capability — is the right follow-up (the four already
  drifted: encryption and vmess `enc` absent from the store step, host only in the gate and
  the step) and is deliberately out of scope here, because moving all four onto one owner
  touches every ingest path and would double this spec.
- Any change to the ordering law, the schema cursor, or `error_kind` (frozen CHECK).
- The `AuthState::NotApplicable` field in the Details pane. Unrelated label, same word.

## 4. Design per item

### 4.1 U1 — the encryption arm

**Contract.** `is_undialable_shape` gains one arm: `ProtocolConfig::Vless(cfg)` returns
true when `cfg.validate().is_err()` (`vless.rs:1367` — the same `SupportError::Config` the
parser and the capability already share). It is evaluated inside the function
`purge_invalid_shapes_once` (`database.rs:474`) already calls, so the DATA step and the
boundary cannot drift again.

**Three-core evidence.** `encryption` is xray's own field; xray's client accepts
`none`/`auto` (restored) or a valid `mlkem768x25519plus` string and errors otherwise.
sing-box has no `encryption` field on `VLESSOutboundOptions`
(`option/vless.go:19-30`) — the value cannot even be expressed. mihomo parses it but its
`encryption.NewClient` accepts only `""`/`"none"` or the mlkem form
(`transport/vless/encryption/factory.go:12-16`), erroring on anything else. So
`aes-128-gcm`, `chacha20-poly1305`, `""`, `tls`, `non`, `ure=0` are dialable by nothing.

**Test.** `#[rstest]` table over `is_undialable_shape`: `encryption="aes-128-gcm"` true,
`""` true (the parser's `<empty>`), a valid `mlkem768x25519plus…` string as stored false,
absent false, `"none"`/`"auto"` false (restored at parse, never stored). Plus one agreement
row: a fixture the capability refuses (`vless_reason(cfg).is_some()`) is also
`is_undialable_shape == true` — the copy-drift guard.

**Risk.** A stored value valid for another implementation is retired. None exists: the
three pins are the implementations.

### 4.2 U3 — the marker bump

**Contract.** `purge_invalid_shapes_once`'s `MARKER_VERSION` goes 3 → 4
(`database.rs:482`), the comment naming the encryption arm. An existing DB re-runs the scan
once on the next open; the key does not change, so no schema cursor moves. The scan already
commits once and refreshes the affected endpoints' ranks (`database.rs:520-541`).

If D2 is approved after this ships it needs its own marker key (e.g.
`deprecated_flows_purged` v1), not a second bump here: the two lists must stay separately
reversible.

**Test.** Fixture DB with one row per new arm plus one live valid row: after open the new
rows carry `purge_reason='config_invalid'` at bin 16, the valid row is untouched; a second
open writes nothing; the v3 arms still behave (a `flow=none` row and an `ss` placeholder row
keep their verdicts).

**Risk.** Irreversible for the 37 retired rows; they are undialable by our engine and by
every in-tree pin (the encryption value has no home in any of the three), and Purgatory
keeps them readable before `purge_expired`, exactly as S5's 143 rows.

### 4.3 D1 — vmess payload ciphers: NOT a boundary item

**Decision recorded: no.** The first draft of this spec proposed the arm on the ground
that `capability.rs:345-349` says xray 26.x rejects `none`/`zero` server-side. That claim
is true **for xray** and was verified at the pin (`common/protocol/headers.pb.go:27-30`
lists only `UNKNOWN/AUTO/AES128_GCM/CHACHA20_POLY1305`; `parseSecurityType` maps anything
else to `UNKNOWN` and the server rejects it, `proxy/vmess/encoding/server.go:114-123`,
`:242`). It is **not** true of the other two pins:

- sing-box: `option/vmess.go:21` declares
  `enum:"auto,none,zero,aes-128-cfb,aes-128-gcm,chacha20-poly1305"` and passes the value to
  its vmess client; `auto` over TLS becomes `zero` (`protocol/vmess/outbound.go:98-104`).
  Provenance: the `zero` arm is proven in-tree — sing-box *chooses* it — while `none` and
  `aes-128-cfb` are enum-declared only, because the client itself
  (`github.com/sagernet/sing-vmess`, `go.mod:59`) is not vendored.
- mihomo: `transport/vmess/vmess.go:85-105` accepts `aes-128-gcm`, `chacha20-poly1305`,
  `none`, `auto`; `zero` is the one value it rejects. `CipherMapping` (`:34-37`) carries
  `none` as first-class. In-tree, no inference.

So an `enc=none` row is dialable by two pinned oracles (mihomo by explicit arm, sing-box by
its option enum) and `enc=zero` by one (sing-box's own TLS path) → the predicate's contract
excludes it. No gate, no purge, no `validate_vmess_shape`. The 13 rows
keep `[n-a]`, which is the truth: *our engine* cannot serve them.

**Doc follow-up (part of U5).** `capability.rs:345-349`'s sentence must be scoped to xray,
because as written it invites exactly the arm this spec withdrew.

### 4.4 U5 — the predicate's contract and its stale examples

**Contract.** `proto_spec/mod.rs:20-30` names three shapes "some pinned oracle still
serves". At the pins:

- **non-vision flows over TLS** — stale. xray 26.11.9 handles `vless.XRV` and `""` only and
  returns `"unknown request flow " + flow` for everything else
  (`proxy/vless/inbound/inbound.go:550-588`); mihomo truncates the flow to 16 bytes and
  rejects anything whose prefix is not `xtls-rprx-vision`
  (`adapter/outbound/vless.go:464-470`); sing-box passes the string straight to
  `github.com/sagernet/sing-vmess/vless` (`protocol/vless/outbound.go:17`, `:95`), which is
  **not vendored** — so the rule was read from the module at the revision sing-box's
  `go.mod` pins (`v0.2.9-0.20261019223527-a0c58542bd9d`): `NewClient` switches on
  `""`/`xtls-rprx-vision` and returns `unsupported flow` for everything else. Correction to
  record: no pin serves a legacy flow, but mihomo
  **does** serve a canonical-prefix flow with junk suffixes appended — the fact U6 uses.
- **legacy SS stream ciphers** — still true; native dials them (`NATIVE_SS_METHODS`).
- **`quic` transport** — still xray-only, still a feature gap, correctly outside the
  predicate.

**Why it matters.** This sentence is what a reviewer cites to reject a new arm, and a stale
example lets either side win on false evidence — this spec's own first draft was that
failure mode. Comment-only change, landed with U1.

### 4.5 U6 — the doubled `-udp443` suffix is an artefact, not a variant

**Contract.** `normalize_flow` (`vless.rs:279`) already collapses `""`/`none` to absent.
Add: if the value starts with `xtls-rprx-vision`, parse the optional single `-udp443`
suffix and **drop any repetition** (`xtls-rprx-vision-udp443-udp443[-…]` →
`xtls-rprx-vision-udp443`). Any other value is kept verbatim for the capability gate to
judge (unchanged).

A marker-gated DATA step rewrites the stored value on rows that carry the repetition, in
the `normalize_encryption_once` shape (`rekey.rs:25-85`): rewrite `protocols.config`, re-key
identities, rebuild the affected `profile_stats` rows, refresh ranks. Rows whose flow is
normalised become dialable; their `[n-a]` clears when the next batch visits them (S10's
refresh path, `ping.rs:2388-2410`), not by the data step.

**Evidence.** mihomo's truncation shows the shape comes from clients that tolerate it, and
xray's addons carry the canonical string on the wire regardless — so the stored repetition
describes no real wire. Counts at the snapshot: 5 rows / 2 configs.

**Test.** Table: `vision-udp443-udp443` → `vision-udp443`; `vision-udp443-udp443-udp443` →
same; `vision-udp443` unchanged; `vision` unchanged; `direct-udp443` **unchanged**
(dropping order is not the law's business); `xtls-rprx-visi` unchanged. Data step: two
stored configs rewritten, identities re-keyed, one link row each still present, second open
no-op.

**Risk.** A re-key rebuilds part of `protocols`/`profile_stats`; the encryption precedent
already does this and its shape is tested. A row could merge with an existing canonical
row — that is the desired dedup, and `merge.rs` evidence law applies as in the precedent.

### 4.6 U4 — marker freshness is visited-only

**Contract.** S10's refresh lives in `ping::after_fast_settle` (`ping.rs:2388-2410`): a
**visited** link gets the current reason, or — when the stored config now passes — falls
through to the probe, whose result overwrites the marker. The precedent's S10 promise
("legacy text + now-supported config ⇒ cleared") is therefore implemented as
*rewrite-or-probe*, not *rewrite-or-clear*: there is no path that clears a marker and leaves
the link untested, and no path that inspects an unvisited row at all. A link outside every
batch's plan scope keeps whatever marker an older build wrote. Measured residual: 5 rows
still carry the removed text `vless account encryption is not implemented` (all 5 purged,
all created 11-12), and 1 live row carries a `muxtype=smux` marker that today parses to
`Named{Smux}`.

**Why the missing clear-half is not a defect here.** A clear without a probe would hand the
link to the ranking law as `bin 12` with no measurement, and the next batch would probe it
anyway — so the probe *is* the clear, with better evidence. What matters is that the
marker's text cannot outlive its config on a visited row, which it cannot.

**Scope.** No sweep. A sweep needs the capability gate plus every stored config outside a
batch scope — the cost S10 deliberately avoided (`ping.rs:2236-2237`) — and would be its own
spec. Record the residual; the reasons are one `GROUP BY` away.

### 4.7 D2 — legacy flows: a list beside the boundary

**Recommendation: yes, but not inside `is_undialable_shape`.** Ground: the value was a
working flow for xray ≤ 1.7 and no **in-tree** pin dials it now (§4.4) — a *retired
variant* under ADR 0018, not an invalid shape. Putting it into the boundary predicate would
contradict that predicate's own contract even with U5's correction in place; the distinction
is exactly what ADR 0018 protects.

**The one check, closed.** sing-box's VLESS client is the unvendored
`sing-vmess/vless`; read at the revision sing-box's `go.mod` pins
(`v0.2.9-0.20261019223527-a0c58542bd9d`), its `NewClient` accepts only `""`/`xtls-rprx-vision`
and returns `unsupported flow: <value>` otherwise. All three pins therefore refuse a legacy
flow — xray by name, mihomo by truncate-and-compare, sing-box by name — so D2's ground is
"measured absence across the pins", not "our engine lacks an arm".

**Mechanism if approved.** `pub fn is_deprecated_shape(&ProtocolConfig) -> bool` in
`leas-proto` (VLESS flow non-empty and outside `{vision, vision-udp443}` **after** U6's
normalisation), its own marker-gated step `app_meta.deprecated_flows_purged` v1, and a
`purge_reason` from the existing CHECK set (`config_invalid` — a new value would be a schema
wipe). The import gate refuses the same predicate by extending `validate_vless_shape`
(it already owns "flow needs a layer"). 4 live rows retire: `direct-udp443` 2, `origin` 1,
`visi` 1.

**Why not "repair".** The direct/origin handshake is not the plain one and the pinned
servers reject the flow by name (`inbound.go:588`); there is nothing to rewrite *to*.
`visi` is a feed-side truncation of `vision` — a 14-byte value no client emits; guessing
which four characters were cut is invention.

## 5. Data and schema impact

| Change | Cursor | Step |
| --- | --- | --- |
| U1 + U3 | none | `invalid_shapes_purged` 3 → 4 |
| U6 | none | **new** `vless_flow_normalized` v1 (rekey-shaped, encryption precedent) |
| D2 (if approved) | none | **new** `deprecated_flows_purged` v1 |
| D3 | none | cell precedence + ADR 0003 amendment |

Expected live `[n-a]`, on the audited DB:

| state | live rows |
| --- | --- |
| today | 76 |
| + U1/U3 (encryption) | 39 |
| + U6 (after the next batch visits the 5 normalised rows) | 34 |
| + D2 (flows) | 30 |
| remainder | vmess 13 (D1 = no) + kinds 13 + `quic` 3 + stale mux 1 |

## 6. Test obligations

- `is_undialable_shape` and (if D2) `is_deprecated_shape` are one `#[rstest]` table each,
  named cases, one row per arm; each table also asserts the capability reader agrees on the
  same fixture, so the copies cannot drift again.
- U6 is a table over `normalize_flow` plus a DB fixture for the data step (rewritten value,
  re-keyed identity, second open no-op).
- The purge step's test observes `purge_reason`, the row's bin (16) and a rank-refresh side
  effect — not a source assertion.
- D3's precedence is one table test on `test_cell_content`.
- `just quality-gate code` is the exit gate. No schema fixture (no cursor change).

## 7. Sequencing

| Stage | Items | Why |
| --- | --- | --- |
| S0 | D2/D3 answered | they decide two of the four mechanisms |
| S1 | U1, U5, U3 | the defect and the doc drift; retires 37 rows, no policy needed |
| S2 | U6 | parse first, data step second; independent of D2 (it removes rows D2 would otherwise claim) |
| S3 | D2 (if approved) | its own list, step and marker |
| S4 | D3 | display only, verifiable once the population has shrunk |

## 8. Risks

1. **Irreversible purge**: 37 rows (U1), 41 with D2. Undialable by our engine and by every
   in-tree pin (D2: see §4.7's sing-vmess caveat); Purgatory keeps them readable until TTL.
   The alternative is a permanent `[n-a]` badge and a probe slot per row.
2. **A fourth/fifth copy of the rule set.** Mitigated by keeping the consts in `leas-proto`
   and reading them from `capability`, `import_export` and `is_undialable_shape`; the
   agreement assertions are the guard.
3. **Over-refusal on a live feed** (D2 only). The import summary already counts refusals
   with a reason histogram; that count is the monitoring surface.
4. **The predicate's contract is load-bearing.** U5 must land with S1: the stale flow
   example is what produced this spec's own withdrawn vmess proposal.
5. **U6 re-keys rows.** The encryption precedent (`rekey.rs`) is the template; a merge with
   an existing canonical row is the intended dedup and follows `merge.rs`.
6. **D3 amends an ADR-recorded precedence.** Record the argument (the purge verdict is
   later and stronger than the refusal it superseded); do not flip silently.

## 9. Decisions (user)

| # | Question | Recommendation |
| --- | --- | --- |
| D1 | Does a payload cipher two pins still serve (vmess `none`/`zero`) join the boundary? | **no** — withdrawn on the three-core evidence (§4.3); the fix is implementing it, not refusing it |
| D2 | Do non-vision flows retire through a deprecation list *beside* the boundary? | **yes** — 4 rows after U6; mechanism in §4.7, explicitly not an `is_undialable_shape` arm |
| D3 | Does a purged row show its purge label instead of `[n-a]`? | **yes** — 84 purged rows currently wear the badge |

## 10. Acceptance

Deterministic gates, run against a copied database (never the live one):

1. **Invariant (this is the gate).** Two halves, both must hold:
   (a) **no** live row's config satisfies the landed predicate —
   `SELECT count(*) FROM profile_stats ps JOIN protocols p ON p.id = ps.protocol_id
   WHERE ps.purge_reason IS NULL AND <predicate on p.config>` equals 0;
   (b) every live `not testable …` row's stored text still equals the reason the shipped
   `support_reason` produces for that config, i.e. the marker and the gate agree. Feeds
   rotate, so an absolute count of `[n-a]` rows is not a gate.
2. **Idempotence.** A second open writes nothing: marker `invalid_shapes_purged` ≥ 4 (and
   U6's own marker ≥ 1) short-circuit; `updated_at` unchanged on every `profile_stats` row.
3. **Snapshot expectation (reported, not the gate).** On the audited 2026-11-26 DB the live
   `[n-a]` count runs 76 → 39 (U1/U3) → 34 (U6, after the next batch visits the normalised
   rows) → 30 (D2). Recorded so a future audit can tell drift from a bug.
4. The encryption arm is refused on both ingest paths (URL and form) and by the parse layer;
   the agreement tables are green. U6's normalised value re-imports as itself (one identity,
   no duplicate row).
5. `just quality-gate code` green; no schema cursor change; `cargo nextest run` unchanged
   except the new rows.
6. Reported, not a gate: per retired row, its source feed, so the next audit can tell a feed
   that keeps publishing a retired shape from one that stopped.

## 11. References

- `docs/aegis/specs/2026-11-19-probe-truth-and-ingest-boundary-design.md` — S5 (boundary,
  first pass), S10 (visited-only refresh), §4.4, §9 decision 4.
- `docs/aegis/adr/0018-deprecation-grounds.md` — the rule; D-C is U1's ground, and D2's
  exclusion from the boundary predicate.
- `docs/aegis/adr/0003-stored-profile-ordering-keys.md` — the cell precedence D3 amends.
- Code: `leas-proto/src/proto_spec/mod.rs:20-47` (predicate + contract);
  `proto_spec/vless.rs:279` (`normalize_flow`), `:1329`, `:1367`;
  `leas-native/src/capability.rs:134`, `:284-340`, `:345-359`;
  `leas-config/src/import_export.rs:170`, `:236`, `:264`, `:297-299`, `:788`;
  `leas/src/ops/profiles.rs:702`; `leas-db/src/database.rs:474-541` (`:482` the marker);
  `leas-db/src/schema/rekey.rs:25-85` (the rekey precedent); `leas/src/ui/profiles.rs:859`,
  `:877`; `leas/src/ops/ping.rs:2388-2410`.
- `thirdparty/Xray-core` @ 26.11.9: `proxy/vless/inbound/inbound.go:550-588` (unknown flow
  rejected), `common/protocol/headers.pb.go:27-30` (vmess enum has no `none`/`zero`),
  `proxy/vmess/encoding/server.go:114-123`, `:242`.
- `thirdparty/sing-box` @ 1.15.0-alpha.13: `option/vmess.go:21` (legacy ciphers in the
  enum), `protocol/vmess/outbound.go:98-104` (`auto` → `zero` over TLS), `option/vless.go`
  (no `encryption` field). Its VLESS/VMess clients live in `sing-vmess`, a module
  dependency (`go.mod:59`) that is **not** vendored: anything about sing-box's per-cipher
  or per-flow runtime behaviour beyond those two in-tree facts is inference.
- `thirdparty/mihomo` @ 1.19.33: `adapter/outbound/vless.go:464-470` (16-byte flow
  truncation vs `XRV`), `transport/vless/encryption/factory.go:12-16` (`""`/`none`/mlkem
  only), `transport/vmess/vmess.go:34-37`, `:85-105` (`none` accepted, `zero` refused).
