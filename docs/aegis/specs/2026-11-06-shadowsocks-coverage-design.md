# Shadowsocks coverage: legacy stream ciphers, import policy, plugin TLS semantics

**Date:** 2026-11-06
**Status:** approved 2026-11-06 — plan: `docs/aegis/plans/2026-11-06-shadowsocks-coverage.md`
**Owns:** the legacy (pre-AEAD) Shadowsocks cipher surface, the SS import-admission
policy, and the SIP003 `tls`/`cert`/`certRaw`/`mode=quic` semantics.
**Supersedes, deliberately:**

- `specs/2026-09-30-ss-plugin-design.md` §3.5 — `cert`/`certRaw` are no longer
  "preserved but never honoured"; they are honoured as an SPKI pin (§5.2), and
  `tls` is no longer a boolean we refuse on a bad value (§5.1).
- §8 of the same spec — the `mode=quic`, `tls=<non-boolean>` and
  `cert`/`certRaw` connect-time verdicts are replaced. `mode=quic` rows are now
  **rejected at import** (§4.3); the other two become servable.
- `plans/2026-09-30-ss-plugin.md` T22 — its stop reason ("the wire could not be
  pinned; the oracle embeds V2Ray 4.38.3 whose source is absent") is **moot**:
  the source is now vendored (§1). The conclusion still stands, for a different
  and stronger reason: no QUIC stack we ship speaks the peer's draft wire (§4.3).

Scope is `leas-proto` (parse/model), `leas-native` (codec, gate), `leas-config`
(import funnel), `leas-tls`/`leas-native::security` (pin plumbing), `leas`
(connect-time core choice). No schema change, no `SCHEMA_VERSION` bump.

---

## 1. Evidence base (vendored, read-only, gitignored)

All under `thirdparty/` (`/thirdparty/**` is ignored; `git check-ignore` verified):

| Tree | Tag/rev | Used for |
|---|---|---|
| `v2ray-plugin` | v1.3.2 `ddd7ab4` | the client-side plugin: option parser, modes, TLS wiring |
| `v2ray-core-v4.38.3` | v4.38.3 | the tree it embeds: TLS root pool, `NoneCipher`, QUIC transport |
| `quic-go-v0.20.1` | v0.20.1 | the exact QUIC stack: draft-29/32/34 only |
| `shadowsocks-rust`, `go-shadowsocks2`, `mihomo`, `sing-box` | existing | rosters and cross-checks |

Pinned facts this spec relies on:

| Fact | Cite |
|---|---|
| `cert`/`certRaw` are a **CA** on the client (`Usage: AUTHORITY_VERIFY`), appended to the **system** pool | `v2ray-plugin/main.go:186-190`, `v2ray-core-v4.38.3/transport/internet/tls/config_other.go:43-52` |
| `tls` is read by **presence only**; its value is never inspected | `v2ray-plugin/main.go:276-278` |
| `mode=quic` builds `quic.Config{Security: NONE}` and forces TLS on | `v2ray-plugin/main.go:137-142` |
| The plugin's server speaks QUIC **draft-29/32/34**, never v1 | `quic-go-v0.20.1/internal/protocol/version.go:21-31` |
| `none` = passthrough: key size 0, IV size 0, no framing of its own | `v2ray-core-v4.38.3/proxy/shadowsocks/config.go:82,185-207` |
| sing-box and mihomo map `cert` to a **client certificate** (mTLS), not a root | `sing-box/transport/sip003/v2ray.go:33-41`, `mihomo/component/ca/config.go:126-131` |
| The engine already has an SPKI pin: chain walk and SAN skipped, `CertificateVerify` still checked | `leas-tls/src/verify/mod.rs:86-113` |
| `security.tls.pin_sha256` already routes into that pin | `leas-native/src/security/fingerprint.rs:159-172`, `security/mod.rs:74` |

Not available in-tree, and stated here so no later reader assumes otherwise: **no Go
or Rust implementation of the legacy stream ciphers exists under `thirdparty/`**
(`shadowsocks-rust`, `mihomo` and `sing-box` all delegate to external crates/libs).
Their oracle is a real server (§6), not a vendored client.

---

## 2. Decisions (user-owned, settled in the 2026-11-06 interview)

| # | Decision | Rejected alternative |
|---|---|---|
| D1 | Implement the **full legacy set natively** (dial + Real Ping + UDP), not a testability fallback through a subprocess | a "probe via subprocess core" owner (bigger surface, fixes classes we did not ask for) |
| D2 | `none` is **rejected at import only when the wire is cleartext** (no TLS-bearing layer) | blanket ban (drops rows TLS protects); shipping it (plaintext in the DB) |
| D3 | Existing bare-`none` rows are **not migrated**: no import refresh ⇒ Stale ≤ `ttl_days` ⇒ deleted ≤ `retention_days` | one-shot delete at startup; a persisted quarantine flag |
| D4 | `mode=quic` rows are **rejected at import** | connect-time refusal (status quo), a draft-29 QUIC stack, sing-box's incompatible wire |
| D5 | `tls` = **presence ⇒ On** (strict parity) | keeping our boolean reading |
| D6 | `cert`/`certRaw` = **SPKI pin, per row, pin-only** (no system roots, no global pool); mismatch ⇒ `[cert]` | reference additive-root semantics; DER-byte pinning |
| D7 | Pin comparison by **SPKI SHA-256**, so a renewal that keeps the key survives | leaf-DER equality (purges every renewal) |
| D8 | Legacy rows keep the **sing-box core stamp** (the subprocess fallback), but connect-time native resolution stops requiring an xray stamp | leaving legacy rows subprocess-only despite native support |

D6 is a deliberate deviation from the reference and is documented as **our
policy** ("a pinned cert is the only trust anchor this row accepts"), not as the
option's upstream meaning.

---

## 3. Legacy cipher surface (D1)

### 3.1 The set

Ten method names, matching the sing-box outbound roster minus the AEAD ones
(`leas-proto/src/proto_spec/core_mapping.rs:32-52`):

| Method | key len | IV len | Keystream |
|---|---|---|---|
| `aes-128-cfb` / `aes-192-cfb` / `aes-256-cfb` | 16/24/32 | 16 | AES CFB-128 |
| `aes-128-ctr` / `aes-192-ctr` / `aes-256-ctr` | 16/24/32 | 16 | AES CTR |
| `rc4-md5` | 16 | 16 | RC4 keyed by `MD5(key ‖ IV)` |
| `chacha20-ietf` | 32 | 12 | ChaCha20 (96-bit nonce) |
| `xchacha20` | 32 | 24 | ChaCha20 (192-bit nonce) |
| `none` | 0 | 0 | passthrough |

Password → master key is the existing `EVP_BytesToKey`-MD5 path
(`protocol/ss/method.rs::password_key`, Classic arm), applied with these key
lengths. `none` ignores the password, exactly as `NoneCipher` does
(`v2ray-core-v4.38.3/proxy/shadowsocks/config.go:185-207`).

Roster note: xray **v5 dropped `none`** (`thirdparty/Xray-core/proxy/shadowsocks/config.pb.go:29-33`
has only the five AEAD types; v4.38.3 still had it, `config.go:82`), so a `none`
row's subprocess fallback is sing-box only — which is what `resolve_core`
already decides (`xray_supports_ss_method("none") == false`).

### 3.2 Method model

`SsMethod` today is `{ aead: SsAead, family: SsFamily }` with
`Classic | Blake3_2022`. The **cipher is the single stored truth**; family
becomes a derived selector, so no field can disagree with the primitive:

```rust
pub enum SsCipher { Aead2017(SsAead), Blake3_2022(SsAead), Stream(StreamCipher) }
pub enum StreamCipher { Aes128Cfb, Aes192Cfb, Aes256Cfb,
                        Aes128Ctr, Aes192Ctr, Aes256Ctr,
                        Rc4Md5, Chacha20Ietf, XChacha20, None }
pub struct SsMethod { pub cipher: SsCipher }          // one field, no duplication
pub enum SsFamily { Classic, Blake3_2022, Stream }    // derived, never stored
```

`SsMethod::family()` derives `Classic`/`Blake3_2022`/`Stream` from the cipher
and is the only thing `ss::connect`, `mux` and the auth-ack path dispatch on;
`key_len()`, `iv_len()`, `kind()` and the AEAD accessor dispatch on the cipher.
`from_method` keeps the existing alias coverage and gains the ten names
(case-insensitive, as today). Every stream method resolves to
`ProtocolKind::Shadowsocks` (the `Stream` family arm of `kind()`).

`resolve_method` (`protocol/ss/mod.rs:31`) stays the single config entry point, so
gate and dial cannot drift — the property `capability.rs` documents.

### 3.3 TCP codec — `protocol/ss/stream_legacy.rs` (new)

Wire is the classic protocol, and it is **not** the AEAD chunk layout:

```
client → server:  [IV] cipher(addr ‖ payload…)          (one keystream, continuous)
server → client:  [IV] cipher(payload…)                 (one keystream, continuous)
```

- One random IV per direction, written before the first byte of that direction.
- The keystream is continuous across writes; state persists for the connection
  (same property `vmess/legacy.rs::Cfb` already pins with `cfb_is_chunking_invariant`).
- `rc4-md5`: the RC4 state is keyed by `MD5(key ‖ IV)`, not by the master key.
- `none`: no IV, no keystream; the stream is the stream.

Implementation reuses existing primitives, no new dependency except one direct:

| Part | Reuse |
|---|---|
| AES CFB-128 | extract the existing `vmess/legacy.rs::Cfb` into `crypto/cfb128.rs`, generic over the AES key size; VMess keeps calling it (its NIST F.3.13 vector and chunking test move with it) |
| AES CTR | `ctr` (already a direct dep, `leas-native/Cargo.toml:44`) |
| ChaCha20 / XChaCha20 | `chacha20` (already in `Cargo.lock` at 0.10.2 via `chacha20poly1305`; promote to a direct dep **with `zeroize`**, per `AGENTS.md`) |
| RC4 | hand-rolled (~30 lines, no `unsafe`), KAT-pinned to RFC 6229; recorded in `docs/reference/crypto-dependencies.md` as C1 (wire mandate) |

`none` reuses the same module as an identity codec rather than a special case in
`ss::connect`.

### 3.4 UDP codec

`protocol/ss/udp.rs` gains a `Stream` arm beside `Classic`/`Blake3_2022`
(`udp.rs:1172`, `:336`):

```
datagram:  [IV] cipher([addr][payload])      fresh random IV per datagram
none:             [addr][payload]
rc4-md5:   RC4 keyed by MD5(key ‖ IV)
```

No session table, no replay window, no padding: those are 2022 concepts. The
existing per-association guards (no chain, no `security` on the UDP path) apply
unchanged.

### 3.5 Capability gate

`capability::ss_reason` (`capability.rs:425-453`) stops refusing the ten legacy
methods — `resolve_method` now resolves them. What remains refused by that
function: unknown method names, kind/family mismatch, the plugin verdicts (§5),
and an unusable 2022 PSK. The existing test
`ss_kinds_are_native_and_legacy_methods_defer` is rewritten to assert the new
partition (legacy supported; `salsa20`/unknown still deferred).

`needs_udp`/fast-level predicates are untouched: legacy rows are ordinary TCP
rows.

### 3.6 Connect-time core choice (D8)

`resolve_runtime_core` (`ops/connect.rs:94-119`) only asks for native when the
link's stamp is `Xray` (or an explicit `native`/`auto` override). Legacy rows are
stamped `SingBox`, so they would never reach the native fast path even with a
native codec. The rule becomes:

> ask native when `kind_supported(kind)` **and** the loaded config passes
> `capability::supported`, unless a `protocol_core_overrides` entry forces a
> concrete subprocess core; on a refusal, fall back to `link.core_type`.

Consequence, stated so it is not a surprise: SS rows using `aes-192-gcm`
(xray roster lacks it, so they are `SingBox`-stamped) also become native-served.
Every other native kind is already `Xray`-stamped, so nothing else changes. The
stamp itself is untouched — it remains the subprocess fallback and the thing
`ConfigBuilder::build` dispatches on. The existing `proxy_all_blocked` and
"config not loaded" refusals keep their precedence over this rule
(`ops/connect.rs:104-116`).

---

## 4. Import admission (D2, D3, D4)

One owner: `leas-config::import_export::validate_ss_config` (renames today's
`validate_ss2022_key`), called from **both** funnels — `parse_share_url`
(`import_export.rs:188`) and the form path
(`leas/src/ops/profiles.rs:716`). A rule here means the row is never stored.

### 4.1 Malformed 2022 PSK (already implemented)

Unchanged: xray's `ParseKey` shape (standard base64 or the literal bytes at the
method's key length; `:`-separated multi-user lists accepted, chacha lists
rejected). See `proto_spec::ss2022_password_usable`.

### 4.2 `none` on a cleartext wire (new)

Rejected unless the row carries a **TLS-bearing layer**:

- `security` is `tls` or `reality`, **or**
- the SIP003 plugin's `tls` key is present (real TLS, §5.1).

`obfs=tls` does **not** count: it is the synthetic hello of the obfs transport,
not encryption (`transport/v2ray/tls_obfs.rs`). This distinction is the whole
point of the rule and gets its own test.

### 4.3 `mode=quic` (new)

Rejected unconditionally. The reason recorded in the manifest/error is
capability, not age: *"v2ray-plugin's server speaks QUIC draft-29/32/34; the
QUIC stack this client ships speaks RFC 9000 v1 — no implementation here can
interoperate, and sing-box's QUIC client is a different wire."*

This reverses the recorded §3.5 stance ("a key that changes the wire and we do
not implement it → named refusal at capability, so the row stays importable and
exportable"). The user decided that a row no stack we ship can dial is better
dropped than stored; the reversal is what makes `[untestable]` dead for **new**
quic rows.

### 4.4 Existing rows

No migration, no delete (D3). The gate stops refreshing them, so they follow the
normal Stale/retention path (`state.rs:758`, `main.rs:528-549`). For those rows
the capability refusals of §5 stay in force — see §8 blast radius.

---

## 5. Plugin semantics (D5, D6)

### 5.1 `tls` — presence ⇒ On

`TlsSetting` collapses to what the reference reads:

```rust
pub enum TlsSetting { Unset, On }   // Off and Invalid are deleted
```

- `tls`, `tls=1`, `tls=0`, `tls=false`, `tls=maybe` — all `On`
  (`v2ray-plugin/main.go:276-278`).
- The `plugin_reason` arm for `TlsSetting::Invalid`
  (`capability.rs:529-533`) and its test row are deleted.
- Identity/export: `On` writes `tls=1`; `Unset` writes nothing (the existing
  elision rule). Rows that carried `tls=0/false` re-key — that is the intended
  correction, and such a row was a dead dial anyway (the real plugin would have
  enabled TLS).

### 5.2 `cert` / `certRaw` — per-row SPKI pin

Semantics (D6/D7): a row that states a certificate accepts **only** a server
whose leaf SPKI SHA-256 equals that certificate's SPKI. No system roots, no
chain walk, no global state. `CertificateVerify` is still verified, so the peer
must hold the key (`leas-tls/src/verify/mod.rs:86-113`).

Implementation:

1. `PluginSpec` gains typed accessors for `cert` (a **local file path**) and
   `certRaw` (a PEM body without headers, wrapped as v2ray-plugin does —
   `main.go:73-76`). They stay in `extra` for identity (already hashed), so no
   identity churn; the spec's "extra = preserved but ignored" doc line for these
   two keys becomes "preserved and honoured" (§3.5 of the plugin spec).

   Prerequisite: the option parser must implement the reference's backslash
   escapes (`v2ray-plugin/args.go:70-108`: `\\`, `\;`, `\=`). `certRaw` is the
   first value that legitimately carries both `=` (base64 padding) and `;`, and
   exporters such as v2rayN emit them escaped (`Handler/Fmt/ShadowsocksFmt.cs:79,258`).
   Rows that carry escapes re-key once; rows without them are unaffected.
2. At link-context construction, when a plugin cert is present, compute the SPKI
   SHA-256 and set it on the TLS opts as the existing pin — **the same field
   `security.fingerprint` already reads**
   (`security/fingerprint.rs:159-172` → `WebPkiVerifier::with_pin`). No new
   verifier, no new root API, **no new crate**: PEM armour is stripped with the
   existing `base64` dependency, and the SPKI is read through `webpki`'s
   `EndEntityCert::subject_public_key_info` (the same parser the verifier already
   uses), hashed with `ring`. Owner: `leas-native/src/security/` beside
   `decode_pin_sha256`.
3. Reading `cert` is a local file read driven by subscription config: read at
   dial time only, cap at 64 KiB, PEM only, no path following outside what the
   string names, and never log the content. An unreadable/unparsable pin fails
   the dial loudly — it must never fall back to system roots.
4. `security.tls.pin_sha256` and a plugin cert on the same row: if both are set
   and their SPKI digests differ, that is an undecidable trust statement →
   capability refusal naming both keys. Equal digests are fine.

Failure mapping: pin mismatch becomes a typed cause, `TlsError::PinMismatch`
(new variant) → `NativeError::CertPinMismatch` (new variant) whose `evidence()` is
`FailureEvidence::CertNotValidForName` → `PurgeReason::CertificateMismatch`,
label `[cert]` (`ui/profiles.rs:612`), row leaves the Active view
(`database.rs:1044`). The DB enum and schema are untouched.

Isolation is structural: the verifier is built per link. The test that pins the
property: row A carries a pin for cert X; row B has no pin and must **not** accept
X (it is self-signed), and row C with a different pin must not accept X either.

---

## 6. Verification

Unit (hermetic):

| Area | Test |
|---|---|
| CFB extraction | existing NIST F.3.13 + chunking-invariance vectors keep passing from the new home; VMess suites unchanged |
| CTR / ChaCha20 / XChaCha20 | NIST SP800-38A / RFC 8439 / draft-irtf-cfrg-xchacha vectors at SS's key and IV lengths |
| RC4 | RFC 6229 vectors; `rc4-md5` = `RC4(MD5(key‖iv))` composition test |
| legacy TCP | deterministic IV → golden ciphertext for `[addr][payload]` across a write split (proves keystream continuity) |
| legacy UDP | per-datagram IV, fresh state per packet; `none` emits no IV |
| import gate | `none` cleartext rejected; `none` + `security=tls` accepted; `none` + `obfs=tls` rejected; `none` + plugin `tls` accepted; quic rejected; 2022 rules unchanged; form path rejects the same rows |
| `tls` | every value spellings ⇒ On, on the wire and through identity/export |
| option escapes | `certRaw=AAA\=BBB` and `host=a\;b` decode exactly like `args.go:indexUnescaped`, and a `\`-free option string is byte-identical to today |
| pin | SPKI match accepted; different key rejected; same key + re-issued cert accepted (D7); row isolation (§5.2); `cert` file missing ⇒ dial error, not a system-roots fallback |
| routing | a `SingBox`-stamped legacy row reaches `CoreType::Native`; a refused config still falls back to the stamp |

Integration (opt-in, `native-e2e`, real cores at `$LEAS_CORE_BIN_DIR`):

- one row per legacy method against a **sing-box 1.13.16** SS inbound (the only
  in-tree-capable server; it is also the only core that still implements `none`,
  xray v5 having dropped it), TCP and UDP;
- the pin rows against a self-signed origin, plus a **negative** row: same
  server without the pin must fail verification (a client that skipped checks
  would otherwise pass);
- plugin rows (`obfs=http`, `mode=websocket`, `mode=websocket;tls`,
  `mode=websocket;tls;certRaw=…`) against the real v2ray-plugin server binaries
  (`XRAY_TUI_PLUGIN_BIN_DIR`), extending the existing 3b matrix;
- a `none` + `security=tls` row, proving the chain wraps the cleartext codec
  (the only shape in which `none` survives the import gate).

Import-gate rows run in the normal suite (no cores, no network).

---

## 7. Risks and non-goals

- **Risk: pin-only is not upstream.** A config that pins a cert but expects the
  server to rotate to a publicly-trusted cert will now be refused (`[cert]`).
  This is the user's chosen policy and is documented as such.
- **Risk: `certbot` renewals rotate the key** (its default; `--reuse-key` is
  opt-in) and therefore purge such a row. acme.sh/Caddy renewals reuse the key
  and survive. Stated behaviour, not a defect.
- **Risk: `cert` is a local file read** driven by feed data. Mitigated by
  dial-time-only reads, a size cap, PEM-only parsing, and no logging.
- **Risk: escape-aware option parsing re-keys rows** whose option string carried
  `\` escapes (only `certRaw`-bearing rows realistically do). Their identity
  changes once, on the first import after the change.
- **Non-goal: QUIC draft-29.** No bespoke QUIC stack; quic rows are dropped at
  import (D4).
- **Non-goal: `none` shipped as a general cipher.** It exists in the native
  codec only for rows whose outer layer is TLS (D2).
- **Non-goal: multi-user 2022 (PSK lists / EIH)** — unchanged from the plugin
  spec; lists stay valid-but-unserved.
- **Non-goal: schemas.** No `PurgeReason`, column or `SCHEMA_VERSION` change.

---

## 8. Blast radius of the quic import drop (must not be stranded)

These paths encode "stored, refused at gate, exempt from fast retirement". New
rows never reach them; existing rows still do, so **every one keeps its
behaviour and only its wording/comment changes**:

- `capability::QUIC_WIRE_UNPINNED` + `plugin_reason`'s quic arm
  (`capability.rs:468`, `:521-522`) — keep refusing; rewrite the text to the
  incompatibility fact, and note that new rows cannot exist.
- `transport/v2ray/mod.rs:39-45` — the "no quic arm, and none is promised" note.
- `protocol/ss/ss_plugin.rs` `resolved_mode`/`tcp_fast_probe_is_meaningful` —
  unchanged (legacy rows still need them).
- `ops/ping.rs` T24 fast-level exemption — unchanged.
- `inbound/outbound.rs`, `ws.rs` quic notes — unchanged.

---

## 9. Documentation updates (part of "done")

- `docs/reference/native-core.md` — SS capability table: Encryption row (legacy
  set + reuse), Auth row (`none` policy), Obfuscation row (`tls` presence, cert
  pin), refusal list.
- `docs/architecture/native-core-integration.md` — the gate paragraph (§ around
  `:204-215`): legacy methods are supported; `none`/quic are import policy; the
  pin is our deviation.
- `docs/reference/crypto-dependencies.md` — new rows: RC4 (hand-rolled, C1) and
  the promoted `chacha20`/CFB-extraction entries, with their KATs.
- `docs/aegis/specs/2026-09-30-ss-plugin-design.md` — a header pointer stating
  which sections this spec supersedes (no rewriting of history).
- `docs/aegis/INDEX.md` — one row for this spec.

---

## 10. Retirement

- `TlsSetting::Off` / `TlsSetting::Invalid` and every match arm on them: deleted.
- `capability.rs`'s `TlsSetting::Invalid` refusal, the `cert`/`certRaw` refusal
  loop, and the legacy-method refusal: deleted.
- `vmess/legacy.rs::Cfb` body: moved to `crypto/cfb128.rs`; the VMess module keeps
  its vector tests and re-exports nothing.
- `validate_ss2022_key` name: replaced by `validate_ss_config` (one gate, three
  rules); no alias.

---

## 11. Acceptance

1. All ten legacy methods dial and pass a real ping natively; a legacy row is
   `CoreType::Native` at connect with a `SingBox` stamp.
2. `none` with no TLS-bearing layer never reaches the DB (URL and form paths);
   `none` with `security=tls` or plugin `tls` imports, dials and pings.
3. `mode=quic` never reaches the DB; existing quic rows still show the
   rewritten capability refusal and still age out.
4. `tls=<any value>` behaves as `On`, on the wire and through export/re-import.
5. `cert`/`certRaw` pins the row to that certificate's SPKI; a different key is
   refused with `[cert]`; a same-key re-issue is accepted; no pin leaks to any
   other row.
6. `cargo nextest run --workspace` green; workspace clippy `-D warnings` clean;
   the `native-e2e` rows of §6 green against real cores (opt-in).
