# Plan: ferrox-derived improvements — protocol wire, transports, TLS engine (TLS 1.2 limits, ECH, ML-DSA-65)

- **Date:** 2026-11-05
- **Specs (inputs):** [`specs/2026-11-05-ferrox-protocol-deltas-design.md`](../specs/2026-11-05-ferrox-protocol-deltas-design.md), [`specs/2026-11-05-ferrox-transport-deltas-design.md`](../specs/2026-11-05-ferrox-transport-deltas-design.md), [`specs/2026-11-05-leas-tls-tls12-coherence-design.md`](../specs/2026-11-05-leas-tls-tls12-coherence-design.md)
- **Spec explicitly out of scope:** `specs/2026-11-05-ferrox-derived-verification-gates-design.md` — no reference-oracle harness, no freshness/leak/fixture gates.
- **Status:** draft — awaiting approval to execute
- **TDD route:** `auto` → **strict** for every task that changes wire bytes (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11); **light** for plumbing (T0, T12, T13, T14) where the gate is a behavioural assertion rather than a vector.

## Goal

Close the gaps the ferrox audit found, in the order that repairs interop first and adds capability last:

1. **Wire parity** — VMess mask+padding, VLESS `encryption`+`flow` composition, response-header strictness.
2. **Reach** — a named, documented limit for the TLS 1.2 CBC suites the roster advertises (serving them is forbidden by `crypto-dependencies.md:53`), legacy VMess (`alterId > 0`) as an opt-in dial path, the WS early data the code claims but does not implement.
3. **Capability** — real ECH, ML-DSA-65 REALITY verification, mKCP masks, socket options.
4. **Measured only** — the two copy-elimination ideas, kept only if a bench pays for them.

**Excluded by owner decision:** ClientHello byte-identity work of any kind, the JA4 roster/generator axis, the BoringSSL padding rule, and any attempt to make ECH a *fingerprint* shape. The roster stays exactly as it is; ECH is an engine capability, verified behaviourally, never by byte equality with uTLS.

## Baseline / Authority Refs

| Input | Where |
|---|---|
| VMess `option = 0` today | `crates/leas-native/src/protocol/vmess/header.rs:96`; clear length field `protocol/vmess/stream.rs:443-444` |
| `alter_id` carried, refused by name | `crates/leas-proto/src/proto_spec/vmess.rs:94`, `:619-624`; refusal `crates/leas-native/src/capability.rs:316-329` |
| VLESS `encryption`+`flow` refusal | `crates/leas-native/src/protocol/vless/mod.rs:79-83` |
| VLESS response-version passthrough | `crates/leas-native/src/protocol/vless/stream.rs:140-151` |
| TLS 1.2 suite table (6 AEAD suites) | `crates/leas-tls/src/crypto/tls12.rs:20-60`; refusal `handshake/mod.rs:1103-1108` |
| Roster advertises CBC / static-RSA | `profiles/generated/chrome.rs:189-190, 250-251` (60 rows, 5 families) |
| Selected suite not validated against the offer | `handshake/mod.rs:1067-1073`, `:1103-1108` (groups/shares/sigalgs *are* checked: `:261`, `:267`, `:508`) |
| ECH is GREASE-only; **`ech=` is parsed and silently ignored** | `spec/mod.rs:105-116`, `hello/mod.rs:200-231`; `TlsOpts.ech` `proto_spec/common.rs:468` has no reader in `leas-native` |
| REALITY verify today | `crates/leas-tls/src/reality/{auth,verify,messages}.rs` — HMAC-SHA512 over the ed25519 pub, no ML-DSA |
| ML-DSA-65 reference semantics | `thirdparty/Xray-core/transport/internet/reality/reality.go:111-127`: signature over `HMAC-SHA512(authKey, ed25519_pub ‖ ClientHello.Raw ‖ ServerHello.Raw)`, carried in `cert.Extensions[0].Value`, ML-DSA-65, empty context; config `mldsa65_verify` (`config.pb.go:43`) |
| `pqv` is the share-link spelling for `mldsa65Verify` | `thirdparty/v2rayN/v2rayN/ServiceLib/Handler/Fmt/BaseFmt.cs:57,198`; `thirdparty/v2rayNG/.../FmtBase.kt:92,114`; `thirdparty/xrat/.../stream.rs:101` (alias table) |
| `pqv` in leas is **write-only** — `SEC_PQV` appears in the emitter, never in a parser | `proto_spec/identity.rs:77`, `common.rs:870` (emit), `common.rs:906` (emptiness check). No read site exists |
| Legacy VMess reference | `thirdparty/v2ray-core-legacy/proxy/vmess/encoding/client.go:76-127` (`idHash`, `hashTimestamp(md5, ts)`, AES-128-CFB header), `auth.go`; `account.go:35` (`NewAlterIDs(protoID, alterId)`) |
| Legacy VMess is still shipped | sing-box threads `AlterId` (`sing-box/protocol/vmess/outbound.go:106`) via `sing-vmess`; **Xray-core has no `AlterId` at all** (grep: zero hits) |
| WS early data | `thirdparty/Xray-core/transport/internet/websocket/dialer.go:143-145`, `hub.go:55-59`; false comment `crates/leas-native/src/transport/v2ray/ws.rs:14-19` |
| ECH reference peer (interop, not bytes) | `thirdparty/utls/ech.go`, `u_ech.go`, `examples/ech/main.go` |
| Crypto governance | `docs/reference/crypto-dependencies.md` §3 inventory, §6 hazmat checklist, §7 vector generators |

## Compatibility Boundary

- **No schema change.** `SCHEMA_VERSION` untouched, no DB migration, no TUI state.
- **Two proto consequences, both named, neither silent:** T6 stops *refusing* an `alter_id` the proto already parses; T7 needs a **read path** for `pqv`, which today exists only as an emitter constant. T7's proto edit (add the parse + decide whether the value lives on `RealityOpts`, where Xray keeps it, or stays on `TlsOpts`) is evaluated on its own and does not ride the rest of the plan.
- **Capability surface moves twice, deliberately:** `capability.rs` drops the `alter_id` refusal (T6) and gains a **refusal** for `ech=` until T9 lands (T9a). Accepting-and-ignoring a privacy knob is the defect class this repo refuses.
- **The TLS fingerprint surface does not move.** No roster edit, no JA4 expectation change, no padding change, no hello-ordering change. T4 changes only the diagnostic for a server-selected suite we refuse; the hello we send is unchanged. T5 adds a rejection path a compliant server never triggers.

## Change Necessity

- VMess `option = 0` — our traffic is the only VMess in the wild with a clear size field and no per-chunk padding (T2).
- `encryption`+`flow` refused — rejects a configuration Xray documents, parses and composes (T3).
- TLS 1.2 CBC — 60 generated profiles promise suites the engine refuses; a legacy server that takes us at our word fails with a message that does not say which suite or which profile (T4). Serving them is forbidden by `crypto-dependencies.md:53`, so T4 fixes the diagnostic and records the limit instead of writing MAC-then-encrypt.
- `alterId > 0` — the refusal is honest but the capability is cheap and the servers exist (T6).
- `ech=` accepted and ignored — the one class of configuration bug this repo treats as worst (T9a).
- WS early data — documented as implemented, absent (T8).

## Ripple Signal Triage

| Surface | Touched by | Note |
|---|---|---|
| `leas-proto` | T7 only | `pqv` read path; needs its own evaluation + tests |
| DB / schema / TUI | none | no new persisted state |
| `capability.rs` | T6, T9a | refusal text changes; `capability` tests move with it |
| e2e harness (`e2e/config.rs`) | T3, T6, T8 | new rows only |
| `docs/reference/native-core.md` | all slices | roadmap rows updated per slice |
| `docs/reference/crypto-dependencies.md` | T0, T7, T9 | CFB-128, ML-DSA-65 verify, HPKE base mode — §3 rows + §6 checklist |

## Plan Pressure Test

1. **T3 (vision over the sealed layer) is the highest-risk item.** Pre-committed fallback: if the encryption layer's Direct handoff cannot be expressed without duplicating the vision state machine, keep the guard, replace its message with one that names Xray's support, and defer composition to its own spec. Decided at T3's spike, never mid-implementation.
2. **T9 (ECH) is the largest new item** (~700-1000 lines: ECHConfigList parse, HPKE base mode on `ring`, outer/inner split, `retry_configs`, acceptance confirmation). It is last in Phase 2 on purpose; T9a ships regardless of whether T9b lands.
3. **T6 (legacy VMess) may be judged not worth it.** Evidence above says two implementations still carry it; it is an opt-in dial path, so the blast radius of being wrong is one refused row.
4. **T7 (ML-DSA-65) is live-ecosystem reach, not a speculative feature.** Xray's server emits it (`reality/config.go:40-44`, `config.proto:11,25`) and every mainstream share-link writer carries `pqv`; what is unknown is how many endpoints in *our* feed set it. It stays abandonable until T0.2 lands the dependency, and mandatory once it does.
5. **T14 (micro-opts) may pay nothing.** Pre-committed rule: ≤5% on the vision record path by criterion means revert + record the rejection. No "it looks faster".

## T0 — Dependency and crypto governance (blocker: T2, T7, T9)

| Step | Change |
|---|---|
| T0.1 | Promote `sha3` (already in `Cargo.lock` at 0.12 via `ml-kem`) to a direct `leas-native` dependency with `zeroize`, for SHAKE128 (T2). |
| T0.2 | Add `ml-dsa` (RustCrypto) to `leas-tls`, **verify-only**: `VerifyingKey::<MlDsa65>` + `verify_with_context(msg, sig, &[])` — FIPS 204 with the empty context, matching Xray's `mldsa.Verify(pk, msg, sig, nil)`. No signing key is ever constructed, so the `zeroize` feature has nothing to wipe on this path; it stays enabled only for symmetry with `ml-kem`. |
| T0.3 | Add **no** `cfb-mode` and **no** `hpke`: AES-128-CFB is ~40 lines over the existing `aes` block cipher (T6); HPKE base mode composes `ring`'s X25519 + HKDF-SHA256 + AES-128-GCM (T9). |
| T0.4 | Three §3 inventory rows in `docs/reference/crypto-dependencies.md`, each with cause + independent oracle + retirement trigger: CFB-128 (NIST SP 800-38A F.3.13), ML-DSA-65 verify (NIST ACVP `ML-DSA-65` sigVer), HPKE base (RFC 9180 A.1-A.6). |
| **Gate** | `cargo deny` / `cargo audit` clean; `cargo hakari` regenerated; `cargo tree -e features \| grep zeroize` shows the feature on both new deps. |

## Phase 1 — wire parity

### T1 — VLESS: non-zero response version is an error
- **Files:** `protocol/vless/stream.rs` (`:140-151`), `protocol/vless/vision.rs` (test only).
- **Change:** hard error naming the byte, `PeelAck::Failed` on the slot. Add the vision-latch test: first chunk < 21 bytes → still matching; ≥ 21-byte mismatch → passthrough for the rest of the stream.
- **Gate:** fake server returning `0x01` surfaces an error, not payload; every existing vision test green.
- **Risk:** low — the removed branch's justification (REALITY fallback) is unreachable; the engine's cert check fires first.

### T2 — VMess: mask + global padding
- **Files:** `protocol/vmess/header.rs` (option byte), `protocol/vmess/stream.rs`, new `protocol/vmess/pad.rs`.
- **Change:** emit `0x04 | 0x08`; SHAKE128-masked 2-byte size field; per-chunk random padding subtracted before open; **pad draw before mask draw** (`Xray-core/common/crypto/auth.go:127-132`, `240-265`). Never set `0x01` (`headers.go:32-33`).
- **Gate:** Go-derived vector for a fixed key/IV/pad length (not a Rust round trip); existing VMess e2e rows against a real xray-core server; a row that rejects a padding length the peer did not use.
- **Risk:** medium — the padding length is never transmitted; both sides derive it from identical generator state, so an off-by-one desynchronises the stream.

### T3 — VLESS: compose `encryption` + `flow`
- **Files:** `protocol/vless/mod.rs` (guard), `protocol/vless/vision.rs`, `protocol/vless/encryption/**`.
- **Change:** lift the guard; on Direct, hand off to the encryption layer rather than the TLS layer — the `CanSpliceCopy = 3` semantics (`Xray-core/proxy/vless/outbound/outbound.go:262-267`).
- **Gate:** e2e `encryption=mlkem768x25519plus…&flow=xtls-rprx-vision` against xray-core; assertion that Direct lands on the encryption conn and the outer TLS records stop being re-framed.
- **Risk:** high — the one task with a pre-committed fallback.

## Phase 2 — reach

### T4 — TLS 1.2: name the suite we cannot serve (documented limit)
- **Files:** `crypto/tls12.rs`, `handshake/mod.rs`, `docs/reference/native-core.md`.
- **Governance conflict resolved:** the first draft of this task proposed hand-rolling `Direction::Cbc`. `docs/reference/crypto-dependencies.md:53` forbids it in as many words — "CBC suites are **refused**, not hand-rolled: HMAC-then-encrypt is exactly the construction that must not be written here". The Lucky13 surface is the record layer, not the block cipher, so no crate purchase removes it. **No CBC code is written.**
- **Change:** the `Tls12Suite::from_u16` miss becomes a typed error carrying the wire id; the twelve refused ids (`0xc013`, `0xc014`, `0xc009`, `0xc00a`, `0x009c`, `0x009d`, `0x002f`, `0x0035`, + the 3DES/RC4 pair) are listed as a named limit in `native-core.md`; `tls12.rs:299` **stays** and gains a comment pointing at the governance row.
- **Gate:** a TLS 1.2 server selecting `0xc013` yields an error naming `0xc013`; a test pins the refused list.
- **Reopen trigger:** a measured counter of real endpoints selecting a CBC suite, then an ADR amending the §3 row (new cause, independent Go/openssl oracle, retirement trigger). Not before.
- **Risk:** none — the only change is the diagnostic.

### T5 — TLS: the selected suite must be one we offered
- **Files:** `handshake/mod.rs`, beside `offered_group` / `offered_share`.
- **Change:** one predicate for both versions; the error names the selected id.
- **Gate:** negative row (known-but-unoffered suite → error); every roster profile's own suite set still passes.
- **Risk:** none. Ships in the same slice as T4 so the validation path is touched once.

### T6 — VMess legacy `alterId > 0` (opt-in dial path)
- **Files:** `protocol/vmess/{header,stream}.rs`, new `protocol/vmess/legacy.rs`, `capability.rs:316-329`.
- **Change:** when `alter_id > 0`: derive the id chain (`NewAlterIDs`-equivalent MD5 chaining), write `idHash(ts)` (16-byte MD5-based hash + u64 timestamp) instead of the AEAD auth block, encrypt the header body with AES-128-CFB under `cmdKey` with the `hashTimestamp(md5, ts)` IV, and use the plain chunk-size parser. Body ciphers unchanged (v2ray-core-legacy's `EncodeRequestBody` keeps AEAD bodies).
- **Gate:** byte vector from `v2ray-core-legacy`'s own encoder for a fixed UUID/alterId/timestamp; e2e against a real v2ray-core or sing-box server with `alterId=4`; a row proving `alterId = 0` still takes the AEAD path.
- **Risk:** medium — a separate wire, so a mistake breaks only this row.

### T7 — ML-DSA-65 REALITY verification
- **Proto change (deliberate, `leas-proto`):** `pqv` moves off `TlsOpts` (`proto_spec/common.rs:467`) onto **`RealityOpts.mldsa65_verify`** (`common.rs:524-530`), the name Xray uses (`mldsa65_verify`, `config.proto:25`) and the location every other implementation puts it (REALITY-only: xrat reads it only under `tls == "reality"`, `xrat/.../stream.rs:84-118`). The share-link key stays `pqv` (`v2rayN BaseFmt.cs:57,198`, `v2rayNG FmtBase.kt:92,114`). `TlsOpts.pqv` is deleted; **no migration is owed** because `SEC_PQV` appears only in the emitter (`common.rs:870`) and there is no reader — no stored config can hold a value.
- **Files:** `leas-proto` (field move + parse + the `:906` emptiness discriminator), `crates/leas-tls/src/reality/verify.rs`, new `crates/leas-tls/src/crypto/mldsa.rs`, `crates/leas-native/src/security/reality.rs`.
- **Change:** after the existing HMAC-SHA512 check (`reality/verify.rs:63-90`), when `mldsa65_verify` is set: `VerifyingKey::<MlDsa65>::decode(pqv)` then `verify_with_context(HMAC-SHA512(auth_key, ed25519_pub ‖ ClientHello.Raw ‖ ServerHello.Raw), cert.Extensions[0].Value, &[])`. Two hard details from `reality.go:111-127`: the signature rides in **extension index 0 by position**, not by name (guard `len(Extensions) > 0`), and the transcript is the **retained raw hello/ServerHello**, never a re-serialisation.
- **Semantics (additive, not a replacement):** ML-DSA success sets `Verified` and skips the system chain; failure falls through to `x509.Verify` (`reality.go:129-138`), which rejects a REALITY cert. No `pqv` ⇒ today's behaviour byte-for-byte.
- **Gate:** NIST ACVP `ML-DSA-65` sigVer vectors through the adapter; a positive fixture generated by Xray's own emitter; negatives — tampered signature, wrong public key, wrong transcript, extension missing.
- **Risk:** medium — the wrong transcript bytes reject every real server, so the fixture must come from Xray and never from our verifier.

### T8 — WS early data
- **Files:** `transport/ws.rs`, `transport/v2ray/ws.rs` (comment).
- **Change:** when `max_early_data` is set, buffer the first protocol write, base64url it into `Sec-WebSocket-Protocol`, send it as the first binary frame after the 101, consume the echoed header as the read prefix. Fix the false comment in the same commit.
- **Gate:** e2e against a real xray-core server with `?ed=2048`; the first payload must ride the upgrade, not a second write. Unit: the header appears only when configured; unconfigured requests stay byte-identical.
- **Risk:** low.

### T9 — ECH: honesty first, capability second
- **T9a (one commit, ships alone):** `ech=` is parsed and ignored. Until T9b, refuse it by name in `capability.rs`, with the same shape as the `alter_id` refusal. Silence is the defect.
- **T9b — Files:** new `crates/leas-tls/src/{ech.rs,hpke.rs}`, `hello/mod.rs` (outer/inner split), `handshake/mod.rs` (accept + confirmation), `client.rs`.
- **T9b — Change:** ECHConfigList parse and selection; HPKE base-mode seal (X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM) on `ring`; SNI suppression in the outer hello and the real SNI in the inner; HRR re-seal; `retry_configs` re-attempt; ECH acceptance confirmation folded into the transcript hash.
- **T9b — Gate:** RFC 9180 A.1-A.6 HPKE vectors; ECH config/parse vectors; **behavioural interop** against `thirdparty/utls/examples/ech` as a peer (acceptance confirmed, SNI hidden from the outer hello, retry honoured). Byte equality with uTLS is explicitly not a gate.
- **Risk:** high — largest new surface; reachable only through the `ech=` knob.

## Phase 3 — remaining transports and engine checks

### T10 — xhttp: padding alphabet, half-open range, per-POST size
- **Files:** `transport/xhttp.rs`.
- **Change:** replace the static `'X'` slice with a token alphabet preserving the 8-bit-Huffman invariant; half-open `[min, max)`; per-request random POST size bounded by `scMaxEachPostBytes`.
- **Gate:** alphabet property test (every emitted char has an 8-bit HPACK Huffman code — the invariant the current comment relies on), bound test (never `max` inclusive), size draws within bound over N draws.
- **Risk:** low.

### T11 — mKCP: masks + capacity knobs
- **Files:** `transport/kcp/**`, new `transport/kcp/mask.rs`.
- **Change:** `original` (FNV cascade) and `mkcp-legacy` (dns/dtls/srtp/utp/wechat/wireguard) with per-connection counters; wire `uplink_capacity`/`downlink_capacity` (already in the proto, `common.rs:313-314`) into `KcpSettings`.
- **Gate:** fixed seed+conv+payload → expected obfuscated bytes (the *expectation* from the pinned Go implementation as a constant, not its harness); existing KCP e2e rows unchanged.
- **Risk:** medium — mask state must match the peer exactly; a counter mismatch is a silent stall.

### T12 — socket2 layer (safe surface only)
- **Files:** new `leas-native/src/sockopt.rs`, `transport/tcp.rs`.
- **Change:** `TCP_USER_TIMEOUT`, keepalive, `SO_REUSEPORT`, `IPV6_V6ONLY`, `TCP_NODELAY`, `TOS` via `socket2`. `SO_MARK` / `SO_BINDTODEVICE` / `TCP_CONGESTION` are **out**: `#![forbid(unsafe_code)]` makes them an ADR, not a task.
- **Gate:** injectable seam test that requested options reach the socket builder; unconfigured dials unchanged.
- **Risk:** low.

### T13 — `Http2Profile` reaches the h2 client, or `headers.rs` dies
- **Files:** `transport/http/conn.rs`, `crates/leas-native/src/headers.rs`.
- **Change:** seed the h2 client's SETTINGS from the resolved `Http2Profile`; give `headers.rs` its stated consumer (ws/httpupgrade/xhttp defaults) or delete it. No third copy of browser truth.
- **Gate:** the peer observes the profile's SETTINGS; if the table is deleted, no dead module remains.
- **Risk:** low.

## Phase 4 — measured only

### T14 — copy elimination in the vision record path
- **Files:** `protocol/vless/vision.rs`, `crates/leas-tls/src/record/stream.rs`.
- **Change (only if paid):** gathered write (uuid + frame head + payload + trailer in one record, no staging `BytesMut`) and in-place reader walk.
- **Gate:** `just bench` shows ≥5% on the vision record path **before** the change is kept; otherwise revert and record the rejection in the spec.
- **Risk:** low — revert-able by construction.

## Non-goals

- ClientHello byte-identity, padding rule, JA4/roster work, ECH fingerprint shapes — excluded by owner decision.
- Verification-oracle harness, freshness/leak/fixture gates, `count-ops`-style gates — excluded spec.
- SS2022 EIH — needs a proto identity list; deferred (protocol spec D4).
- Static-RSA TLS 1.2 suites — decided by evidence at T4's e2e; if no reachable server selects them, a named limit is documented instead of implemented.
- gRPC `TunMulti`, xmux pooling, xhttp h3 changes, `downloadSettings` — unchanged deferrals.

## Execution order (one slice per landing, full gate each time)

`T0 → T1 → T2 → T3 → T5+T4 → T6 → T7 → T8 → T9a → T10 → T11 → T12 → T13 → T9b → T14`

Rationale: T3 (highest risk) runs immediately behind the two safety nets it needs — T1's stricter peel and T2's proof that the shared record path can change safely without desynchronising — while the blast radius is still small. T9b is last because it is the only task that can be dropped without leaving a claim unmet, once T9a has made `ech=` honest.

## Execution notes (2026-11-05)

### Landed

| Task | Result |
|---|---|
| **T0** | `shake` promoted to a direct `leas-native` dependency (SHA3 0.12 no longer carries the XOF types, so the XOF crate is the one to depend on); `ml-dsa 0.1.2` added to `leas-tls` with `default-features = false` (verify-only, no RNG/PKCS#8); **no** `cfb-mode`/`hpke` deps — CFB is 60 lines over `aes`, HPKE was not needed (T9b deferred). `cargo hakari generate` regenerated the unification crate and its machete ignore list gained `shake`. Gates: `cargo deny check bans licenses sources` ok, `cargo machete --with-metadata` clean, `cargo audit` unchanged (1 pre-existing allowed warning). |
| **T1** | Non-zero VLESS response version is `InvalidData` naming the byte and setting `AuthAck::Failed`; the passthrough field, its poll_read branch and `PeelAck::NotApplicable` are gone. The vision UUID-latch test the spec asked for already existed (`unpad_uuid_gate_mismatch_commits_passthrough`, `unpad_short_header_passes_through_without_committing`) and still pins the behaviour. |
| **T2** | VMess option `0x0c` (mask+pad), SHAKE128 size mask + `next()%64` cleartext padding with the pad-before-mask draw order, header padding nibble (`dice.Roll(16)`), and a keystream **rollback** so a sealed-but-unwritten datagram returns both its counter and its SHAKE slot. Goldens: the header wire came from an independent Go oracle that first reproduces the pre-change Xray-verified golden byte for byte; the keystream is pinned against `hashlib.shake_128`. UDP send cap corrected to `8192-2-16-64`. |
| **T3** | `encryption` + `flow` compose: `connect_vision_over` runs the vision pipeline over the sealed conn, and `DirectMode` for the boxed seam resolves an `mlkem` `CommonConn` to a **no-op** handoff (the sealing layer keeps framing — `CanSpliceCopy = 3`). The old config refusal is gone and the dispatch test proves the failure is now a transport one. |
| **T4/T5** | TLS 1.2 CBC/static-RSA stay unserved (governance row `:53`), but the miss is now a named typed error carrying the suite id and its name (`REFUSED_TLS12_SUITES` + `refused_suite_name`), pinned by a test. The ServerHello's chosen suite is validated against the hello we actually sent (`ensure_offered_suite`), parsed back from the wire rather than the spec. |
| **T6** | Legacy VMess: `protocol/vmess/legacy.rs` (CFB-128 with the NIST F.3.13 vector, `idHash` prefix, `hashTimestamp` IV) + `VmessClientStream::new_legacy` (4-byte response peel, plain size field, CFB-decrypting read wrapper). `capability.rs` no longer refuses `alter_id`; its test flipped to "supported". Header test pins the prefix against an independent md5 and decrypts the body back to the `0x01`-option layout. |
| **T7** | `pqv` moved from the dead `TlsOpts.pqv` to `RealityOpts.mldsa65_verify` (serde alias `pqv`, accessor, share-link parse in vless+trojan, emitter moved to the REALITY block). `leas-tls` verifies `ML-DSA-65` over `HMAC-SHA512(auth_key, ed25519_pub ‖ CH ‖ SH)` with the signature taken from certificate extension **index 0**; keys/messages/signatures are Go 1.27 `crypto/mldsa` vectors. |
| **T8** | WS early data: `EarlyDataDial` defers the upgrade to the first protocol write, puts up to `max_early_data` bytes in `Sec-WebSocket-Protocol` (URL-safe base64) and sends them as the first frame. Deferral keeps the upgrade inside the caller's future, so a rejected handshake still surfaces as `TransportRejected`. |
| **T9a** | `ech=` is refused by name in `capability.rs` (`tls ech is not implemented`) — no more accept-and-ignore. |
| **T10** | xhttp padding is drawn from the 8-bit-Huffman set (`&*,;XZ`) over a half-open `[100, 1000)`, and each POST draws its own size below `scMaxEachPostBytes`. Tests assert the alphabet invariant, the half-open bound, and dense seq order with full coverage. |
| **T12** | `sockopt.rs`: the safe `socket2` surface, applied through `SockRef` at the TCP dial (today: `TCP_NODELAY`, the historical behaviour). Every other option is present but unset until a config surface exists; `SO_MARK`/`SO_BINDTODEVICE`/`TCP_CONGESTION` remain ADR-gated. |
| **T13** | `h2_client_with(stream, profile)` seeds hyper's stream/connection windows from `leas_tls::Http2Profile` resolved from the SAME fingerprint the hello used; xhttp and v2rayhttp pass it. `headers.rs` stays as the sweep tool it is (its h2 table already delegates to the engine). |

### Deferred / not attempted, with the reason

- **T9b (real ECH)** — no verifiable peer offline: uTLS's ECH test server needs Go modules the sandbox cannot fetch (`go build ./transport/internet/finalmask/...` in `thirdparty/Xray-core` fails on `proxy.golang.org` fetches, and the same applies to the ECH example). Shipping an ECH client whose only test is self-consistency would be worse than the honest refusal T9a now performs. `thirdparty/utls/ech_test.go` carries the ECHConfigList vectors for the follow-up.
- **T11 (mKCP masks)** — blocked on two counts. (a) **The plan under-specified the work**: the masks are selected by config (`finalmask.udp`: `original`, `mkcp-legacy` header families — `thirdparty/Xray-core/transport/internet/finalmask/mkcp/{original,header}/`), and `leas-proto` has no such field, so serving them needs a proto/share-link decision the plan does not carry — hard-coding one would silently change every existing KCP dial. (b) **No runnable oracle**: `go build ./transport/internet/finalmask/...` fails here on `proxy.golang.org` fetches, so a Rust port could only be pinned against itself. The two capacity knobs stay unread for the same slice.
- **T14 (micro-opts)** — the rule was "keep only if `just bench` shows ≥5% on the vision record path". The bench cannot run here: `cargo bench -p leas-native --features native-e2e --bench throughput` prints `SKIP throughput vless/vision+reality: core missing` for every row because `LEAS_CORE_BIN_DIR` has no real core binaries. With the gate unreachable, no code was written.

### Gate output

- `cargo fmt` clean; `cargo clippy -p leas-native -p leas-tls -p leas-proto --all-targets` **0 warnings**;
- `cargo nextest run --workspace`: **2670 passed, 11 skipped**. 
- deps gates as above.
