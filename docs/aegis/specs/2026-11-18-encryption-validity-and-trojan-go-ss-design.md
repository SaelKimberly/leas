# Encryption validity and the Trojan-Go SS layer — Design Spec Brief

Date: 2026-11-18
Status: **implemented 2026-11-18** — every rule below was grilled and decided in
session 2026-11-18; D15 = **A** (identity normalisation DATA step). Implementation:
`plans/2026-11-18-encryption-validity-and-trojan-go-ss.md` (executed; gate 3/3,
2 814 tests; Trojan-Go oracle 17/17). ADR 0017 records the decision.
Origin: `[ n-a]` rows on a live feed, traced to a `vmess://` URI-form link mishealed as
VLESS; and the Trojan `encryption` parameter, which the parser drops.
Related: `specs/2026-09-22-native-testability-improvement-design.md` (mlkem
classification), `specs/2026-11-06-shadowsocks-coverage-design.md` (classic AEAD
stream), `specs/2026-11-12-first-flight-coalescing-design.md` (`HeaderFirst`),
`specs/2026-09-30-ss-plugin-design.md` (SIP003 `plugin=` grammar).

---

## 1. Why this exists

### 1.1 The mishealed row

A stored VLESS row carries `"encryption":"aes-128-gcm"` and the marker
`not testable by the native engine: vless account encryption is not implemented`.
Its source is group `kort0881:ru:white`
(`…/checked/RU_Best/ru_white_all_WHITE.txt`), revision `da0562531449`
(2026-10-07T05:23:49Z), line 1607:

```
vmess://5c040f1d-45db-43bd-8d46-e4950e433735@141.95.65.9:1234?allowInsecure=1&encryption=aes-128-gcm&security=tls&sni=supervpn.super.com&type=tcp#[341ms Германия DE 🇩🇪 @vlesstrojan]
```

The declared scheme is `vmess://`, but the body is URI-form. `VmessConfig` requires
base64 JSON and returns `InvalidStructure(SchemeX::Vmess)` (`vmess.rs:113`), a
*recoverable* error; the fallback chain (`proto_spec/mod.rs:195-260`) then runs
`Ss → Ssr → Vmess → Vless`, VLESS accepts the body (UUID userinfo, `:1234`, query
values), and `vless.rs:325` stores `encryption` verbatim. The row was never a VLESS
link.

Stored VLESS rows (`~/.config/xray-tui/data.db`, 2026-11-18):

| `encryption` | rows |
| --- | --- |
| absent / `none` | 8 610 |
| valid `mlkem768x25519plus…` | 207 |
| `auto` | 9 |
| `none=/@Telegram…` (glued remark) | 2 |
| `aes-128-gcm` | 1 |

Cross-check against the reference: xray-core 26.3.27 refuses `encryption:"auto"` at
config build (`VLESS users: unsupported "encryption": auto`, exit 23), and accepts no
non-mlkem value but `none`. sing-box has no such field and ignores it.

### 1.2 The second ingestion path

The Clash VLESS conversion copies `encryption` verbatim
(`vless.rs:793`, `ClashVless.encryption`), while the URL parser drops `none`
(`vless.rs:325-328`). A Clash row carrying `encryption: "none"` is therefore stored
as `Some("none")`, passes `capability` (which accepts `none`), and dies at dial:
`connect` sends every non-empty value to `connect_encrypted`, whose mlkem parser
returns `Ok(None)` → `unsupported encryption value none`. The same path would store
`auto`/junk untouched. Validation therefore belongs to one shared normaliser used by
both ingestion paths, not to the URL parser alone.

### 1.3 The dropped Trojan parameter

`trojan.rs:22` documents Trojan-Go's `encryption=ss;method:password` layer, but
`try_parse_proto` never reads the key (`SecurityConfig.enc` is `None` in both security
arms), and `connect` writes the Trojan header onto the plain stream. A
`trojan://…encryption=ss;…` link is therefore stored and dialed as plain Trojan: a
silent wrong wire. `trojan-go://` links do not parse at all (no `SchemeX` variant).

---

## 2. Decisions (locked in session 2026-11-18)

| # | Decision |
| --- | --- |
| D1 | Parse permissively, validate strictly. A config that fails validity is a parse error and is **not imported** (Option C). |
| D2 | VLESS restores `auto` and a `none`+junk suffix to *absent* `encryption` (generator confusion / glued remark). |
| D3 | VLESS rejects every other value, including malformed mlkem. Full mlkem validation (grammar + decoded keys + padding blocks) moves to `leas-proto`; `leas-native` consumes the validated value. |
| D4 | Trojan `encryption` is implemented client-side: `ss;<method>:<password>` with exactly `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`; `none`/absent is plain Trojan; everything else is invalid. |
| D5 | Trojan-Go link surface: `type=original` restores to TCP; `plugin=…` is invalid (transport plugins are unimplemented); `sni`/`host`/`path`/`type=ws` unchanged. |
| D6 | `trojan-go://` becomes a scheme; reconstruction emits `trojan-go://` iff the SS layer is present, else `trojan://`. |
| D7 | Every other share-link parser rejects any `encryption` presence, including `none` and empty. |
| D8 | The fallback chain stops on `InvalidConf`; structural errors still continue. |
| D9 | No cleanup, deletion or reclassification of already-stored **invalid** rows. `capability::support_reason` re-runs the same validator as the backstop, so a stale invalid row stays visible, exportable and never dialed. |
| D10 | The SS layer is a **bare AEAD stream**, not an SS target-address session (`core.Cipher.StreamConn`, `tunnel/shadowsocks/client.go`). It is inserted between the secured/transported stream and the Trojan request header. UDP associate is wrapped by the same layer. |
| D11 | Composition is allowed on every Trojan security/transport the parser accepts; the oracle proves raw/TLS and ws/TLS. |
| D12 | No Trojan mux, no server side, no add-server form field (link import only). |
| D13 | External builders (`xray`, `sing-box`, Clash) refuse a row carrying the layer instead of silently dropping it. |
| D14 | Oracle: pin Trojan-Go v0.10.6 as a fourth core, rows for all three ciphers across raw and ws. |
| D15 | Stored-row identity: one-time DATA step behind an `app_meta` marker (no DDL, no cursor bump): normalise the stored `auto`/`none`-junk VLESS configs, re-key, merge collisions. §8. |

---

## 3. Part A — encryption validity contract

### 3.1 Rules

| Parser | Value | Verdict |
| --- | --- | --- |
| `vless` | absent | valid, `encryption: None` |
| `vless` | `none` (ASCII case-insensitive) | valid, `None` |
| `vless` | `none` followed by a garbage suffix (first suffix byte ∈ `= / @ # ? & ; ,` or whitespace) | valid, restored to `None` |
| `vless` | `auto` (ASCII case-insensitive) | valid, restored to `None` |
| `vless` | valid `mlkem768x25519plus…` | valid, kept verbatim |
| `vless` | empty, `aes-128-gcm`, malformed mlkem | `InvalidConf("encryption", value)` |
| `trojan` | absent, `none`, `none;<ignored params>` | valid, no field (Trojan-Go validates only the `ss` params) |
| `trojan` | `ss;<method>:<password>` | valid, typed field (§4.2) |
| `trojan` | `ss;…` with unknown method, empty password, missing `:` | `InvalidConf` |
| `trojan` | empty, a provider other than `ss`/`none`, any other value | `InvalidConf` |
| `trojan` | duplicate `encryption` key | `InvalidConf` (Trojan-Go rejects it; `url/share_link.go:147`) |
| `anytls`, `http_client`, `hysteria1`, `hysteria2`, `shadowtls`, `ss`, `tuic`, `wireguard` | any `encryption` key present | `InvalidConf("encryption", value)` |
| `vless` | duplicate `encryption` key | first wins (existing `query_get`; no reference contract) |

Restoration applies only to the owning parsers. `none` is the only accepted foreign
value *for VLESS/Trojan*; on a non-owner even `none` is invalid, because the parameter
should never appear there (D7).

The rules are applied by **one normaliser per owner**, called from every ingestion
path:

- VLESS: `normalize_vless_encryption(raw: &str) -> Result<Option<TinyText>, ParseError>`
  — used by `try_parse_proto` (`vless.rs:325`) and `try_from_clash_proto`
  (`vless.rs:793`); `VlessConfig::validate()` applies the same function to a stored
  value.
- Trojan: the parse-time check lives in `try_parse_proto`; the Clash struct carries no
  `encryption` field, so there is no second path.

### 3.2 Owners

- `leas-proto::proto_spec::vless::parse_mlkem_encryption` grows the decoded form:
  `keys: Vec<MlkemKey>` (32/1184 bytes) and `padding: PaddingSpec { lengths, gaps }`.
  `parse_padding` and the base64 key decode move here from
  `leas-native/src/protocol/vless/encryption/mlkem.rs::EncryptionConfig::try_from_parsed`.
  The three codec rules (triple shape, first block `prob ≥ 100 && min ≥ 35`, total
  `≤ 65553`) move with them. `leas-native` builds the handshake from the proto value;
  it keeps no second parser.
- `VlessConfig::validate(&self) -> Result<(), SupportError>` re-runs the same check for
  stored/deserialised configs; `capability::support_reason` calls it (D9). Reason text
  names the value: `vless encryption \`<value>\` is not a VLESS encryption value`;
  malformed mlkem keeps the parser's specific sub-reason.
- Trojan and the foreign-presence check are parse-time only: the configs do not carry
  the key, so no stored config can be invalid on this axis.

### 3.3 Fallback chain

`try_parse_proto`'s primary attempt already returns `InvalidConf` immediately. The
fallback block (`proto_spec/mod.rs:252-260`) is changed to stop on `InvalidConf` as
well: a structural failure means "the body is not mine, try the next parser"; a
config-invalid result means "the body is mine and broken", so reinterpreting it as
another protocol is wrong. With this rule the source URL dies at VLESS and never
reaches Trojan/Hysteria2 (which accept any userinfo; `trojan.rs:92`,
`hysteria2.rs:108`).

Measured risk: no body in the six feeds of 2026-11-18 makes a non-owning parser return
`InvalidConf`; SS/SSR/VMess fail structurally on non-base64 userinfo.

---

## 4. Part B — Trojan-Go SS layer

### 4.1 Reference wire

Trojan-Go v0.10.6 (latest release, GitHub API 2026-11-18) composes the client stack as
`transport → tls → websocket → shadowsocks → trojan → mux → simplesocks → router`
(`proxy/client/client.go:24-42`). The SS tunnel wraps the carrier with
`c.Cipher.StreamConn(conn)` (`tunnel/shadowsocks/client.go`): a bare shadowsocks AEAD
stream (salt ‖ sealed chunks), **without** an SS target-address header — the Trojan
header inside it carries the target. The share-link grammar is
`url/share_link.go:143-185`; the URL-option mapping is `url/option.go:82-90`.

### 4.2 Model

```rust
pub struct TrojanConfig {
    // …
    pub encryption: Option<TrojanEncryption>,
}

pub enum TrojanEncryption {
    Ss { method: TrojanSsMethod, password: String },
}

pub enum TrojanSsMethod { Aes128Gcm, Aes256Gcm, Chacha20IetfPoly1305 }
```

- Serde spelling is the lowercase hyphenated method name via explicit `#[serde(rename)]`
  (`aes-128-gcm`, …); deserialisation rejects any other value,
  so a stored config cannot name an unimplemented cipher.
- Identity: `method` enters the signature stream; `password` enters the credential
  stream (`w.cred("trojan_ss_password", …)`), never `sig`. `None` writes nothing, so
  every existing Trojan identity is unchanged.
- Parse: split the percent-decoded query value with `SplitN(';', 2)` then
  `SplitN(':', 2)`; provider and method are matched ASCII case-insensitively and
  normalised to lowercase (Trojan-Go's own parser is strict-lowercase; permissive
  parsing is D1). Empty password, missing `:`, unknown method/provider → `InvalidConf`.
- Export: `encryption=ss;<method>:<password>` percent-encoded (`;` → `%3B`,
  `:` → `%3A`), the spelling Trojan-Go's `net/url` parser decodes.

### 4.3 Scheme and link surface

- Add `SchemeX::TrojanGo` (`trojan-go`), the `trojan-go://` pattern in
  `slice_input`, and a dispatch arm to `TrojanConfig::try_parse_proto` (the body
  grammar is identical to Trojan's).
- `type=original` is added to `recover_transport_type`'s known spellings → TCP.
- `plugin` presence in a Trojan link is `InvalidConf` (D5); the SS SIP003 parser keeps
  its own `plugin` handling untouched.
- `reconstruct_proto` chooses the scheme: `trojan-go://` when `encryption` is `Some`,
  `trojan://` otherwise.

### 4.4 Connect placement

```
security (TLS/REALITY) → transport (ws/grpc/…) → SsStream (bare AEAD) → HeaderFirst(trojan request)
```

- `protocol/ss/stream.rs` gains a crate-internal
  `wrap_bare(stream, method, password) -> Result<BoxStream, NativeError>` that builds
  `SsStream::new(..., first: None)` and does **not** flush eagerly; the first write
  emits `salt ‖ sealed chunks`. Sending the SS address header (as `connect_to` does)
  would be wrong for this layer.
- `protocol/trojan::connect` wraps its `stream` before `HeaderFirst`; `connect_udp`
  wraps before writing its command-3 header. The read direction consumes the server's
  salt on first read; Trojan has no response header, so the tunnel is the wrapper.
- No new crypto or dependency: `method.rs`/`stream.rs` already implement all three
  ciphers and the classic AEAD stream.

### 4.5 Composition and refusal

- Allowed on every security (`tls`, `reality`, `none`) and transport the Trojan parser
  accepts (D11). The layer is orthogonal to framing.
- `inject_to` (xray/sing-box) and `to_clash_proto` return a named error when
  `encryption.is_some()`: neither core carries the field, and emitting the row without
  it would silently change the wire (D13). Clash import cannot produce the layer
  (no field), so no reverse mapping is added.
- `capability::support_reason` is unchanged for Trojan transport-wise; the typed field
  admits only implemented ciphers, and a `capability` refusal is not needed.

---

## 5. Oracle

- Add `Core::TrojanGo` to `leas-oracles/src/pins.rs` (`TROJAN_GO_VERSION = "0.10.6"`),
  asset names `trojan-go-linux-amd64.zip`, `trojan-go-linux-armv8.zip`,
  `trojan-go-windows-amd64.zip`, `trojan-go-windows-arm64.zip` (the 64-bit ARM linux
  asset is spelled `armv8`). SHA-256 from the
  release `digest` when GitHub publishes it, otherwise computed once and pinned; the
  source date is recorded next to the constant.
- Pin table: `just oracles-pins xray singbox mihomo trojan-go` (the recipe gains a
  fourth argument and a Trojan-Go asset filter).
- `CoreKind::TrojanGo`, `bin_name = trojan-go`, spawn `trojan-go -config <path>`,
  readiness by the existing TCP-connect probe. Version sanity via `-version`.
- Server JSON (keys confirmed by the implementation against the pinned binary):
  `run_type: "server"`, `local_addr`/`local_port` (the harness port), `remote_addr`/
  `remote_port` (the echo), `password: ["<pw>"]` (array; `statistic/memory/config.go`),
  `ssl: { cert, key }` (harness `Certs` PEMs), `shadowsocks: { enabled: true, method,
  password }`, `log_level: 0`.
- Rows in `crates/leas-oracles/tests/trojan.rs`: `(aes-128-gcm, tcp)`,
  `(aes-256-gcm, ws)`, `(chacha20-ietf-poly1305, tcp)`. Trojan-Go is the server; the
  native client is under test. A fourth row may repeat a cipher with `encryption=none`
  as the control.

---

## 6. Acceptance criteria

| # | Observable |
| --- | --- |
| A1 | The exact URL in §1.1 is rejected by `try_parse_proto` with a config-invalid reason and is never stored. |
| A2 | `encryption=auto` and `encryption=none=/@Telegram…` VLESS links parse to `encryption: None` and export without the parameter; the same values through Clash conversion give the same result, and Clash `encryption: aes-128-gcm` is rejected (today it is stored and never dialable). |
| A3 | A padding-malformed mlkem value is rejected inside `leas-proto`; a valid one still passes `pq_enc_vless_supported`. |
| A4 | Trojan `encryption=none` parses plain; `ss;…` parses typed; `ss;bogus:…`, empty password, duplicate key, `plugin=…` are rejected. |
| A5 | `trojan-go://…?encryption=ss%3Baes-256-gcm%3Apw…` parses, `type=original` → tcp, and the oracle rows echo bytes through the layer. |
| A6 | Unit test: the first client bytes are `salt ‖ length-seal`, with no SS address header before the Trojan hash. |
| A7 | Export of an ss row emits `trojan-go://…encryption=ss;method:password…` and re-parses to the same config; a plain row still exports `trojan://`. |
| A8 | Identity: differing SS password → different credential id; differing method alone → different sig; `None` → existing uid unchanged. |
| A9 | xray/sing-box/Clash conversion of an ss row returns a named error, not a config without the layer. |
| A10 | Existing parse/healing/e2e tests remain green. |

---

## 7. Non-goals

Trojan-Go server side; Trojan mux and simplesocks; transport plugins; an add-server
form field; cleanup or reclassification of stored invalid rows; new cipher families.

---

## 8. Stored rows and identity (D15 = A)

No schema bump: `trojan-go` is not a stored kind, and the new Trojan field is optional
(`None` writes nothing). Two stored-row consequences remain:

1. **Invalid rows stay** (D9): the `aes-128-gcm` row and any future stale invalid row
   keep their ids and become capability-marked with a named reason. No deletion.
2. **Identity normalisation changes uids for restored VLESS rows.** Rows stored with
   `encryption: "auto"` (9) or `none=<junk>` (2) will re-import as `encryption: None`,
   a different `uid`; refresh never prunes unseen rows, so re-import creates duplicate
   protocol rows for the same link.

**Decision (D15 = A):** a one-time DATA step behind an `app_meta` marker (no DDL, no
cursor bump, per AGENTS): rewrite those 11 stored VLESS configs to `encryption: None`,
recompute `sig`/`cred`/`uid`, repoint `profile_stats`, and merge into the existing id
when the normalised uid already exists. Option B (accept duplicate rows) was rejected
because it leaves the same node twice, permanently, with no pruning path.

Trojan rows imported before this change from `ss;…` links cannot be recognised (the
parameter was dropped), so they stay as plain Trojan rows; the new import creates the
correct row. No migration exists for that case, and the current six feeds contain no
`ss;` value.

ADR signal: the fourth oracle core (a pinned third-party binary is a durable
dependency) and the parse/validation boundary (invalid configs are not imported; the
fallback chain stops on `InvalidConf`) are ADR-worthy. Record the ADR when the change
ships, not at design time.

---

## 9. Evidence limits

- No live Trojan-Go run was performed during design. The wire facts come from the
  v0.10.6 source; the oracle rows are the first execution.
- Feed counts (0 `trojan-go://` links, 0 `encryption=ss;` values) are from the six
  groups configured on 2026-11-18; they do not bound what users paste.
- Composition outside raw/TLS and ws/TLS is analytic (D11).
- The fallback-terminal rule's blast radius is bounded by the six feeds, not proven
  exhaustively.

## 10. References

- Trojan-Go v0.10.6: `proxy/client/client.go:24-42`, `tunnel/shadowsocks/client.go`,
  `tunnel/shadowsocks/config.go`, `url/share_link.go:17-30,143-185`,
  `url/option.go:82-90`, `proxy/option.go:96`, `statistic/memory/config.go:8`,
  `constant/constant.go:4`.
- Local: `crates/leas-proto/src/proto_spec/{mod.rs,vless.rs,trojan.rs,common.rs}`,
  `crates/leas-native/src/protocol/{vless/encryption/mlkem.rs,ss/stream.rs,trojan/mod.rs}`,
  `crates/leas-native/src/capability.rs`, `crates/leas-oracles/src/{pins.rs,e2e/core.rs,e2e/case.rs,e2e/harness.rs}`.
