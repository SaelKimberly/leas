# Design: `leas-tls` TLS 1.2 coherence — advertised suites, selected-suite validation, BoringSSL padding

- **Date:** 2026-11-05
- **Status:** **draft — awaiting approval.** Read-only audit; no code touched.
- **Kind:** spec
- **Owners:** `crates/leas-tls/src/{crypto/tls12.rs,record/**,handshake/mod.rs,hello/mod.rs}`, `crates/leas-tls/src/profiles/generated/**` (read-only input)
- **Evidence base:** `thirdparty/ferrox` @ `188d80d` (its `crates/ferrox-core/src/tls/shaped/**` is a hand-written TLS client with its own record layer) plus **primary sources in this checkout**: `thirdparty/utls/u_tls_extensions.go:1125-1140` (`BoringPaddingStyle`), `thirdparty/Xray-core`. Ferrox's `docs/` were not used.
- **Relationship to `2026-11-05-leas-tls-fidelity-design.md`:** that spec owns the *roster/hello/REALITY/JA4* axis (S1–S7, implemented). This one owns the **engine's ability to serve what the roster advertises**, the handshake's conformance checks, and the padding rule. No item here re-opens an item there.

## 1. Witness verdicts

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| L1 | The roster advertises CBC and static-RSA suites that `Tls12Suite` cannot parse, so a server that picks one is refused | **CONFIRMED — 60 rows across 5 families** | Advertisement: `profiles/generated/chrome.rs:189-190` (`0xc013, 0xc014, 0xc009, 0xc00a`), older rows also `0x009c, 0x009d, 0x002f, 0x0035` (`chrome.rs:250-251`); rows carrying `0x009c`: chrome 14, chrome_android 15, firefox 8, safari 6, safari_ios 17. Engine: `crypto/tls12.rs:20-60` maps six ECDHE-AEAD suites and nothing else; the refusal is explicit at `handshake/mod.rs:1103-1108` ("CBC suites are not"). A test **pins the gap as intended**: `crypto/tls12.rs:299` `assert_eq!(Tls12Suite::from_u16(0xc013), None); // CBC: unsupported`. |
| L2 | leas never checks that the server's chosen suite was one we offered | **CONFIRMED** | `handshake/mod.rs:1067-1073` (1.3) and `:1103-1108` (1.2) validate only that the id is *known*, not that it was advertised. Groups, key shares and signature algorithms **are** checked (`:261`, `:267`, `:508`, `:719`, `:734`) — the suite check is the one hole. Ferrox has the same hole (`crates/ferrox-core/src/tls/shaped/client.rs:415-418`, `:508-511`); that is not a reason to keep it. |
| L3 | leas pads **every** ClientHello below 512 bytes; BoringSSL pads only 256–511 | **CONFIRMED against the primary source** | leas: `hello/mod.rs:63` `PADDING_TARGET = 512`, applied `:416-419` `512.saturating_sub(acc_record + 4)`, so a 200-byte hello grows a padding extension Chrome never sends. uTLS, which is what Xray actually runs: `thirdparty/utls/u_tls_extensions.go:1125-1140` — `if unpaddedLen > 0xff && unpaddedLen < 0x200 { … }`, else no extension at all. Ferrox matches uTLS (`hello.rs:1008-1015`). Consequence is an extra extension (extension count and JA4_c shift) on short hellos only. |
| L4 | leas's TLS 1.2 suites are GCM/ChaCha only; ferrox has CBC, 3DES, RC4 and static RSA | **CONFIRMED both sides** | leas `crypto/tls12.rs:20-33`; ferrox `tls/shaped/record.rs:17-60`, `tls/shaped/rsa.rs`, `tls/shaped/tls12.rs:13-80`, verified against Go's own records by `shaped/oracle.rs:334-420` (16 suite rows). |
| L5 | leas's hello builder is byte-gated only by JA4 | **CONFIRMED** | `tests/generated_ja4_gate.rs` hashes the built hello; JA4 is order-insensitive and slot-blind inside the cipher list, so cipher order, GREASE slots, padding position and extension bodies are unobserved. Ferrox gates hello **bytes** against uTLS presets (`hello.rs:1326-1400` vs `scripts/utls-oracle/expected.txt`). |
| L6 | leas already does things ferrox gets wrong | **CONFIRMED** | Session-id echo check `handshake/mod.rs:1063-1069` (ferrox discards it, `client.rs:1391`); `compress_certificate` decompression `handshake/flight.rs:305-335` (ferrox advertises `0x001b` and has no `0x19` handler); signature-algorithm membership `ensure_offered_sigalg` `handshake/mod.rs:508`. |
| L7 | leas's REALITY auth matches Xray byte-for-byte | **CONFIRMED — no action** | Session-id plaintext layout, HKDF label `"REALITY"`, AAD-over-zeroed-id and nonce offsets all match `Xray-core/transport/internet/reality/reality.go:166-199` per the fidelity spec's G3 verdict and `reality/messages.rs:23-40`. Ferrox agrees (`reality.rs:1229-1266`). Nothing to adopt. |

## 2. Defects, ranked

| Rank | Item | Consequence | Class |
|---|---|---|---|
| 1 | **Advertise-what-you-cannot-serve** (L1) — **accepted limit after the D1 reversal** | A legacy TLS 1.2 server that selects `0xc013` fails the handshake, and the engine is *detectably* incoherent (a real Chrome offered that suite and would have completed). It stays unfixed on purpose: serving it means hand-rolling MAC-then-encrypt, which `crypto-dependencies.md:53` forbids outright. What changes here is the *diagnostic* (the error names the suite and the profile) and the *record* (a documented limit + a counter). | accepted limit |
| 2 | **Selected suite not validated against the offer** (L2) | A hostile or broken server can force a suite we never offered. Protocol conformance only (no key-strength escape today, because the mapping is closed), but it is a one-screen fix and RFC 8446 §4.1.3 requires it. | conformance |
| 3 | **Padding rule** (L3) | Extra extension on short hellos; JA4_c and extension count differ from Chrome. Only reachable for hand-selected short specs, not the generated roster (all ≥ 512 once padded). | fingerprint |
| 4 | **No byte-level hello gate** (L5) | Any future roster edit can change cipher order, a GREASE slot or an extension body without a failing test. | verification |

## 3. Errata — ferrox TLS behaviours NOT to copy

| Item | Evidence | Why not |
|---|---|---|
| No session-id echo check, no compression-method check | `shaped/client.rs:1391-1392` | leas already checks; ferrox is the regression. |
| Advertises `certificate_compression` (`0x001b`) with no `0x19` handler | `profiles.rs:151,174` vs `client.rs:1500+` | A server that honours it kills the handshake. leas implements decompression. |
| `randomized` profile generator: hardcoded weights, one draw per **process** (`OnceLock`) | `shaped/mod.rs:244-295`, `:180-236` | Correlates every dial from one process and is unverifiable. |
| `*_psk` names resolve to profiles that carry no PSK extension, gated against an `OmitEmptyPsk`-modified golden | `shaped/mod.rs:92-101`, `scripts/utls-oracle/main.go:127-133` | Gating against a doctored reference is worse than no gate. We either emit `0x0029` or refuse the name — see D4. |
| 3DES and RC4 suites | `shaped/record.rs:17-60` | Broken/removed by every browser we mimic. Implementing them makes our hello a lie in the other direction. |
| `unsafe` hello reader (`from_raw_parts_mut` + `set_len`) | `crates/ferrox-core/src/tls/reality.rs:620-632` | `leas-tls` forbids `unsafe`. |
| Fixed REALITY server cert validity `260101…`/`491231…` | `reality.rs:977-978` | Constant fingerprint; server-side only anyway. |

## 4. Decisions

- **D1 — the advertised CBC suites stay UNSERVED, and the refusal becomes a named, documented limit.** This reverses the first draft of D1, which proposed hand-rolling `Direction::Cbc`. That draft contradicted a standing rule: `docs/reference/crypto-dependencies.md:53` records `leas-tls/src/crypto/tls12.rs` under cause C1 with the explicit posture "CBC suites are **refused**, not hand-rolled: HMAC-then-encrypt is exactly the construction that must not be written here". The Lucky13 timing surface is in the record layer, not in the block mode, so no crate purchase removes it — the rule holds. S1 therefore does what is cheap, honest and reversible: the refusal names the suite and the profile that advertised it, the limit is recorded in `docs/reference/native-core.md` with the twelve suite ids, and the handshake error stops saying "CBC suites are not supported" in favour of naming the exact value and the fix (a profile whose hello omits it, or an ADR). **Reopening requires evidence, not preference:** a measured counter of real endpoints selecting a CBC suite, then an ADR that amends the §3 row with a new cause, an independent Go/openssl oracle and a retirement trigger. Static RSA (`0x009c/0x009d/0x002f/0x0035`, 60 rows) inherits the same posture for the same reason; 3DES and RC4 remain rejected outright.

- **D2 — validate the selected suite against the offered list** (both versions). One predicate next to the existing `offered_group`/`offered_share` helpers; error text naming both the selected id and the offer count.
- **D3 — [OWNER: deferred, not adopted] padding follows uTLS exactly**: add the extension only when the unpadded record length is in `(0xff, 0x200)`, to a total of `0x200`, with the uTLS `4+1` special case. `PADDING_TARGET` becomes a bound, not a floor. Cite `thirdparty/utls/u_tls_extensions.go:1125-1140` in the comment.
- **D4 — session resumption / PSK stays out; names that imply it stay refused.** leas has no `0x0029` support and ferrox's is a lie (Errata). If a profile id that promises PSK is resolvable today, it must be **refused by name** like the other unusable spellings, never silently mapped to a non-PSK spec.
- **D5 — [OWNER: deferred, not adopted] the byte oracle is adopted** (see the verification spec for the harness): a Go program over `thirdparty/utls` renders each roster profile with entropy zeroed; a Rust test replays the same profile through our builder and diffs the bytes. This is the only gate that sees cipher order, GREASE slots and bodies. JA4 stays as a coarse second gate.

## 5. Slices

| Slice | Change | Gate |
|---|---|---|
| **S1** | Named limit, not a CBC implementation: the `Tls12Suite::from_u16` miss becomes a typed error carrying the wire id and the advertising profile; the twelve refused ids are listed in `native-core.md`; the `assert_eq!(from_u16(0xc013), None)` at `tls12.rs:299` is **kept** (it now documents the policy, not a gap) and gains its cause | A handshake against a TLS 1.2 server that selects `0xc013` produces an error naming `0xc013`, not the current generic message; a test pins the suite list that is refused. No record-layer construction is added, so no cryptographic gate is owed. |
| **S2** | Static-RSA ids join the same named limit (D1) | Same test shape as S1; no premaster-decrypt code. |
| **S3** | Offered-suite validation (D2) | Negative test: server selects a known-but-unoffered suite → error naming it. Positive: every roster profile's own suite set still passes. |
| **S4** | *[OWNER: deferred — see §6]* Padding rule (D3) | Unit: 255-byte record → no padding; 256-byte → padded to 512; 511-byte → padded to 512; 512-byte → untouched. Golden: `thirdparty/utls` renders the same three lengths, byte-equal. |
| **S5** | *[OWNER: deferred — see §6]* Byte oracle wiring (D5) | Fixture is data; the test fails on any body/order drift across all 69 rows. |

## 6. Non-goals

- **TLS 1.0/1.1, fallback SCSV, renegotiation** — no browser we mimic offers them.

### Owner decisions that *left* this file (2026-11-05)

- **Real ECH is IN** (plan T9), as an **engine capability, not a fingerprint**: the goal is a working ECH client (ECHConfigList, HPKE base mode, outer/inner split, `retry_configs`, acceptance confirmation) verified *behaviourally* against `thirdparty/utls/examples/ech`. Byte equality with uTLS and any ClientHello-shape work are explicitly **out**. Sequencing: `ech=` is refused by name first (T9a), because today the knob is parsed and silently ignored (`TlsOpts.ech` `proto_spec/common.rs:468`, no reader in `leas-native`).
- **ML-DSA-65 REALITY verification is IN** (plan T7) — a **decision, not an absence**: the ecosystem ships it today (`thirdparty/Xray-core/transport/internet/reality/config.go:40-44` builds the server key from `mldsa65_seed`, `config.proto:11,25` are the wire fields, `reality.go:111-127` is the client check), and every mainstream share-link writer carries it as `pqv` (v2rayN, v2rayNG, xrat). What is unknown is adoption in our own feed, not support in the ecosystem. The share-link field moves to `RealityOpts.mldsa65_verify` in T7 — the name and the location Xray and the other clients use — because leas's `TlsOpts.pqv` has no reader at all.
- **Padding rule (D3 / S4) and the byte oracle (D5 / S5) are OUT** by owner decision: the roster and the hello builder stay exactly as they are, so the `(0xff, 0x200)` divergence is recorded here as an accepted, documented limit rather than fixed. If the roster is ever regenerated, reopen S4 first.

## 7. Verification plan

- S1 owes no cryptographic proof: no record-layer construction is added. Its gate is diagnostic — a TLS 1.2 server that selects `0xc013` yields an error naming `0xc013`, and the refused-suite list is pinned by a test.
- S4 (padding) is owner-deferred; if it is ever reopened, its golden must come from `thirdparty/utls`, never from our own builder.
- No existing test is deleted. `crypto/tls12.rs:299` **stays** and gains a comment pointing at the governance row, because the policy it asserts is now deliberate.
