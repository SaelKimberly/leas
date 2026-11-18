# Encryption validity and the Trojan-Go SS layer — implementation plan

Date: 2026-11-18
Status: **executed 2026-11-18.** T1–T10 landed; `just quality-gate code` 3/3
(fmt, clippy, 2 814 tests) and the Trojan oracle suite 17/17, including the three
Trojan-Go v0.10.6 rows. Decision record: ADR 0017.
Spec: `specs/2026-11-18-encryption-validity-and-trojan-go-ss-design.md` (approved
2026-11-18, D15 = A)
Source: grilling session 2026-11-18, decisions D1–D15 in the spec.

## Goal

Two deliverables on one contract:

1. Encryption values are validated at ingestion: VLESS restores `auto`/`none`-junk,
   full `mlkem768x25519plus` validity moves into `leas-proto`, every other protocol
   rejects a foreign `encryption` key, the fallback chain stops on `InvalidConf`, and
   stored invalid rows are refused by `capability` instead of dialed.
2. Trojan-Go's `ss;method:password` layer is implemented as a **bare AEAD stream**
   between the transport and the Trojan header, with `trojan-go://` support, export,
   a stored-row identity normalisation DATA step, and a pinned Trojan-Go oracle.

## Approved scope

| Decision | Value |
| --- | --- |
| Invalid config | parse error, not imported (D1) |
| VLESS restore | `auto` (ci) and `none` + junk suffix → absent; nothing else (D2) |
| VLESS reject | empty, foreign values, malformed mlkem; full mlkem validation in `leas-proto` (D3) |
| Trojan grammar | `ss;<method>:<password>`, methods `aes-128-gcm`/`aes-256-gcm`/`chacha20-ietf-poly1305`; `none`/absent plain; else invalid (D4) |
| Trojan-Go surface | `type=original` → TCP; `plugin=` invalid (D5) |
| Scheme | `trojan-go://` added; export it iff the layer is set (D6) |
| Foreign keys | every other query parser rejects any `encryption` presence (D7) |
| Chain | fallback stops on `InvalidConf` (D8) |
| Stored invalid rows | kept, capability-backstopped, never dialed (D9) |
| SS layer | bare AEAD stream, no SS address header; TCP header and UDP associate both wrapped (D10) |
| Composition | every Trojan security/transport; oracle proves raw+TLS and ws+TLS (D11) |
| Non-goals | mux, server side, add-server form, plugins (D12) |
| Builders | xray/sing-box/Clash refuse a layered row (D13) |
| Oracle | Trojan-Go v0.10.6, 3 cipher/transport rows (D14) |
| Stored rows | one-time DATA step: normalise 11 VLESS rows, re-key, merge collisions (D15 = A) |

## Architecture and owners

- `leas-proto` owns every validity rule: `parse_mlkem_encryption` (grammar + keys +
  padding), `normalize_vless_encryption`, `VlessConfig::validate`, the Trojan
  `encryption` field/grammar, the foreign-presence helper, and the fallback policy.
- `leas-native` consumes validated values only: the mlkem handshake takes the proto
  value; `capability` calls `VlessConfig::validate`; the Trojan connect wraps the
  carrier with the existing classic-AEAD `SsStream` (`first: None`).
- `leas-db` owns the DATA step, reusing `schema/rekey.rs`'s rebuild/merge machinery —
  no second identity implementation.
- `leas-oracles` gains a fourth core; Trojan-Go is the server, the native client is
  under test.

## Tech stack

Rust 2024, `cargo` only. No new crate: the three AEAD ciphers and the bare stream
already exist (`protocol/ss/{method,stream}.rs`); the oracle fetches a pinned Go
binary.

## Baseline / authority refs

- `AGENTS.md`: schema cursor rule (a DATA step is marker-gated, no cursor bump), test
  shape, hot-path rules, oracle pin policy (`pins.rs` + `just oracles-pins`).
- `docs/reference/protocols.md` (VLESS `encryption`, Trojan row), `docs/reference/native-core.md`
  (VLESS encryption row), `docs/reference/database-manual-sql.md` (raw SQL causes).
- Trojan-Go v0.10.6 source: `proxy/client/client.go:24-42`,
  `tunnel/shadowsocks/client.go`, `url/share_link.go:143-185`, `url/option.go:82-90`,
  `statistic/memory/config.go:8`, `proxy/option.go:96`.
- Local code: `proto_spec/{mod,vless,trojan,common,identity}.rs`,
  `leas-native/src/protocol/{vless/encryption/mlkem.rs,ss/stream.rs,trojan/mod.rs}`,
  `leas-native/src/capability.rs`, `leas-db/src/schema/{mod,rekey}.rs`,
  `leas-oracles/src/{pins.rs,e2e/{core,case,config,harness}.rs}`.

## Compatibility boundary

- No `SCHEMA_VERSION` bump and no `IDENTITY_VERSION` bump. The DATA step uses a new
  `app_meta` marker (`vless_encryption_normalized`); existing identities are untouched
  except the rows it rewrites.
- Trojan config JSON gains an optional `encryption`; `None` serialises nothing, so all
  existing Trojan identities are unchanged.
- `trojan-go://` is added to the URL scheme table; the config model still stores
  `ProtocolKind::Trojan`.
- Invalid rows already stored keep their ids and become capability-marked (D9).
- Clash cannot express the layer: conversion refuses instead of dropping it (D13).

## TDD route

`TDD Route: auto — strict.` Authority: writing-plans auto classification (behaviour,
wire contract, persistence). Test posture: failing test first for every behaviour
task, then the minimum implementation, then the same test green; table tests for the
value rules; a real-core oracle row for the wire. Verification is the command named in
each task plus the final gate.

## Verification

| Surface | Command |
| --- | --- |
| proto rules | `cargo nextest run -p leas-proto` |
| native encryption/capability/Trojan | `cargo nextest run -p leas-native` |
| DATA step | `cargo nextest run -p leas-db` |
| oracle compile without cores | `LEAS_ORACLES_SKIP_DOWNLOAD=1 cargo nextest run -p leas-oracles --no-run` |
| real Trojan-Go interop | `cargo nextest run -p leas-oracles --test trojan` |
| full gate | `just quality-gate code` |

---

## Tasks

### T1 — proto owns full mlkem validity

**Files:** `crates/leas-proto/src/proto_spec/vless.rs`,
`crates/leas-native/src/protocol/vless/encryption/{mlkem.rs,mod.rs}`,
`crates/leas-native/src/protocol/vless/mod.rs`, `crates/leas-native/src/capability.rs`.

**RED:** add proto tests that today fail because padding is unvalidated:
`mlkem768x25519plus.native.1rtt.1-2-3.<key>` (first block `< 35`),
`…100-35-70.0-0-0.…` > 65553 total, decoded key of 33 bytes, non-numeric triple.

**Change:** move `ServerKey` (as `MlkemKey`), the base64 key decode, `parse_padding`
and its bounds into `leas-proto`; `MlkemEncryption` carries `keys`, `padding_lens`,
`padding_gaps`; `parse_mlkem_encryption` performs the full validation. In native,
delete `EncryptionConfig` and the native `ServerKey` entirely: `handshake(stream,
&MlkemEncryption)` consumes the proto value and imports `MlkemKey`; `connect_encrypted`
parses through the proto function. `capability::mlkem_encryption_supported` becomes
`parse_mlkem_encryption(enc).is_ok_and(Option::is_some)` (T2 later routes capability
through `VlessConfig::validate`).

**GREEN:** the proto tests, the existing native handshake/KAT tests, and
`pq_enc_vless_supported`/`malformed_pq_enc_vless_deferred`.

**Retirement:** no second padding/key parser remains in `leas-native`.

### T2 — VLESS normaliser applied to every ingestion path

**Files:** `crates/leas-proto/src/proto_spec/vless.rs`, `crates/leas-native/src/capability.rs`.

**RED:** rstest table over `normalize_vless_encryption`/`try_parse_proto`:
`auto`→`None`, `AUTO`→`None`, `none=/@Telegram…`→`None`, `none`→`None`,
`aes-128-gcm`→`InvalidConf`, `""`→`InvalidConf`, valid mlkem kept;
`try_from_clash_proto` with `encryption: Some("none")`→`None`, `auto`→`None`,
`aes-128-gcm`→error. Today the Clash `none` row stores `Some("none")`.

**Change:** add `normalize_vless_encryption(raw) -> Result<Option<TinyText>, ParseError>`
and use it at `vless.rs:325` and `vless.rs:793`. Add
`VlessConfig::validate() -> Result<(), SupportError>` with the named reason
(`vless encryption \`<value>\` is not a VLESS encryption value`; malformed mlkem keeps
its sub-reason). `capability::vless_reason` calls `validate()` first, replacing T1's
local proto check.

**GREEN:** the table, the existing VLESS round-trip tests, and a capability test for a
directly constructed stored config with `aes-128-gcm`.

### T3 — Trojan model, grammar, scheme, and export

**Files:** `crates/leas-proto/src/proto_spec/{trojan.rs,mod.rs,common.rs}`,
`crates/leas-proto/src/urlx/schemex.rs`.

**RED:** rstest table — `trojan-go://pw@h:443?encryption=ss%3Baes-256-gcm%3Apw` parses
to `TrojanEncryption::Ss`; `encryption=none`, `none;x` plain; `ss;bogus:pw`,
`ss;aes-256-gcm:` (empty), `ss;aes-256-gcm` (no colon), `encryption=aes-128-gcm`,
duplicate `encryption`, `plugin=v2ray-plugin` all `InvalidConf`;
`type=original`→TCP; serialize/deserialize of `TrojanSsMethod` uses the hyphenated
spelling; reconstruct emits `trojan-go://…&encryption=ss%3B<method>%3A<password>` and a
plain row emits `trojan://`.

**Change:** add `TrojanConfig.encryption: Option<TrojanEncryption>`,
`TrojanEncryption::Ss { method, password }`, `TrojanSsMethod` with explicit
`#[serde(rename)]`; `write_identity` writes the method in the sig stream and the
password via `w.cred("trojan_ss_password", …)`; `try_parse_proto` validates the query
(provider/method case-insensitive, normalised lowercase; duplicate detection by
scanning `parse_query` pairs); `reconstruct_proto` appends the encoded value and picks
the scheme; `SchemeX::TrojanGo` + `slice_input` + dispatch + `as_known_str`;
`recover_transport_type` gains `original`.

**GREEN:** the table plus the existing Trojan round-trip tests.

### T4 — external builders refuse a layered row

**Files:** `crates/leas-proto/src/proto_spec/trojan.rs`.

**RED:** `inject_to(Xray)` and `inject_to(SingBox)` on an ss config return
`SupportError::Config("trojan-go shadowsocks encryption is not supported by <core>")`;
`to_clash_proto` returns `ProtoSpecError::Unsupported("trojan-go encryption")`; the
same calls on a plain config still succeed.

**Change:** early named errors in `inject_to` and `to_clash_proto` when
`encryption.is_some()`.

**GREEN:** those tests and the existing builder tests.

### T5 — foreign `encryption` and the terminal fallback rule

**Files:** `crates/leas-proto/src/proto_spec/{utils,mod,anytls,http_client,hysteria1,hysteria2,shadowtls,ss,tuic,wireguard}.rs`.

**RED:** a table feeding `encryption=none` (and `encryption=`) to each non-owner parser
expects `InvalidConf`; the exact §1.1 `vmess://…aes-128-gcm…` URL expects an error (not
a VLESS or Trojan row); an existing structural-healing URL still heals.

**Change:** `utils::reject_foreign_encryption(&query) -> Result<(), ParseError>`
called after `parse_query` in the eight parsers; in `try_parse_proto`'s fallback block,
stop on `InvalidConf` instead of trying the next candidate.

**GREEN:** the table, the source URL, and the existing healing tests.

### T6 — bare AEAD wrapper and Trojan wiring

**Files:** `crates/leas-native/src/protocol/ss/stream.rs`,
`crates/leas-native/src/protocol/trojan/mod.rs`.

**RED:** a duplex test wraps the client side with `wrap_bare` and decrypts the first
bytes with the server half: they are `salt ‖ length-seal ‖ sealed(hash…)`, with no SS
address header; `connect` on a layered config writes the Trojan hash only inside the
AEAD stream; `connect_udp` wraps the command-3 header the same way.

**Change:** `pub(crate) fn wrap_bare(stream, method, password)` builds
`SsStream::new(…, first: None)` and does not flush; resolve the method from
`TrojanSsMethod`; in `connect`, wrap before `HeaderFirst`; in `connect_udp`, wrap
before writing the header.

**GREEN:** the new tests, the existing Trojan connect/UDP tests.

### T7 — Trojan-Go oracle core

**Files:** `crates/leas-oracles/src/pins.rs`, `crates/leas-oracles/build.rs`,
`justfile`, `crates/leas-oracles/src/e2e/{core,harness,case,config}.rs`,
`crates/leas-oracles/tests/common/mod.rs`, `crates/leas-oracles/tests/trojan.rs`.

**Change:** `Core::TrojanGo`/`TROJAN_GO_VERSION = "0.10.6"`; assets
`trojan-go-linux-amd64.zip`, `trojan-go-linux-armv8.zip`,
`trojan-go-windows-amd64.zip`, `trojan-go-windows-arm64.zip`; SHA-256 from the release
`digest` when present, else computed once (record the source date); `just oracles-pins`
gains the fourth argument/filter; `CoreKind::TrojanGo` with `bin_name`/spawn
`-config`/`-version` sanity; a `CaseSpec` ss field and `config::trojan_go_server`
(`run_type: server`, `local_addr/port`, `remote_addr/port`, `password: ["…"]`,
`ssl: { cert, key }`, `shadowsocks: { enabled, method, password }`, `log_level: 0`);
`Cores` resolves the fourth binary; three rows `(aes-128-gcm, tcp)`,
`(aes-256-gcm, ws)`, `(chacha20-ietf-poly1305, tcp)` plus an `encryption=none` control.

**Verify:** `LEAS_ORACLES_SKIP_DOWNLOAD=1 cargo nextest run -p leas-oracles --no-run`;
then `cargo nextest run -p leas-oracles --test trojan`. Read the Trojan-Go log
(`LEAS_CORE_LOG=1`) before blaming the client if a row is red.

### T8 — identity normalisation DATA step (D15 = A)

**Files:** `crates/leas-db/src/schema/{mod,rekey}.rs` (new module or an addition to
`rekey.rs`), `crates/leas-db/tests/*`.

**RED:** an integration test seeds protocols with `encryption` `auto`, a glued `none`,
and plain `none`, plus a collision target with the normalised uid; after `migrate`:
configs rewritten to absent, ids re-keyed, the collision merged by the existing merge
law, `profile_stats` repointed, the marker set; a second `migrate` changes nothing.

**Change:** extract `rekey_in`'s body into `rebuild_identities(tx)` (no marker) and
have `rekey_once` call it + stamp `IDENTITY_VERSION`; add
`normalize_encryption_once(conn)` gated by `app_meta.vless_encryption_normalized`:
one Immediate transaction — read protocols, rewrite VLESS configs through
`normalize_vless_encryption`, `UPDATE protocols SET config`, run
`rebuild_identities(tx)`, stamp the marker. Call it after `rekey_once` on the current
and migrating paths, and stamp it on the fresh path.

**GREEN:** the integration test; existing `rekey` tests.

### T9 — docs

**Files:** `docs/reference/protocols.md`, `docs/reference/native-core.md`,
`docs/aegis/INDEX.md`, this spec's status.

**Change:** VLESS `encryption` table (restore/invalid rules, proto owns validation);
Trojan row (Trojan-Go `ss;…`, `trojan-go://`, bare-stream placement, refused
builders); plan/spec status.

**Verify:** `rg` for the old "vless account encryption is not implemented" claims and
for a stale `trojan-go` gap note; no test.

### T10 — gate

`just quality-gate code` (fmt + clippy + default tests) and
`cargo nextest run -p leas-oracles --test trojan` green. Record the exact rows and the
Trojan-Go version in the closing report.

---

## Risks

1. **Trojan-Go binary in CI.** A static Go build should run in the `ubuntu:22.04`
   container; if it does not, the row is a harness blocker, not a client verdict —
   record it and keep the hermetically proven parts green. The oracle is the chosen
   evidence route (spec D14).
2. **Terminal `InvalidConf`.** It ends healing for any candidate that reports a
   config-invalid body. The six feeds show no such case; a future one is a wrong
   *drop*, not a wrong protocol.
3. **DATA step on a live DB.** It rewrites 11 rows and merges collisions on open; the
   marker makes it once-only and the transaction makes it atomic. The user's DB is
   declared test data.
4. **`parse_padding` move** changes error paths; capability text for malformed mlkem
   must keep naming the sub-reason.
5. **Bare-stream framing** is the one wire assumption not yet run; T7 is the proof. A
   failure there is a client bug or a harness/config mismatch; read the server log
   first.

## Retirement

- The native `EncryptionConfig` parser and `parse_padding` are deleted, not retained as
  a second owner.
- The old capability text for stored encryption rows is replaced by the validator's
  named reason.
- No compatibility shim: `trojan://` plain rows keep working; layered rows are new.

## Execution route

**Inline.** The chain is cross-crate and sequential (proto types feed native, native
feeds the oracle); independent subagents would serialize on the same files.
`User confirmation required: no` — no new authorization, privacy or irreversible
boundary beyond the user's D15 choice.
