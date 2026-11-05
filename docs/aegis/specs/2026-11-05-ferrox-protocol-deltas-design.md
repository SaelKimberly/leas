# Design: Protocol fidelity deltas — what `thirdparty/ferrox` proves about VLESS/VMess/Shadowsocks-2022

- **Date:** 2026-11-05
- **Status:** **draft — awaiting approval.** Read-only audit; no code touched.
- **Kind:** spec
- **Owners:** `crates/leas-native/src/protocol/{vless,vmess,ss}/**`, `crates/leas-proto/src/proto_spec/` (VMess `security`/option surface only)
- **Evidence base:** `thirdparty/ferrox` @ `188d80d` (199 `.rs`, ~304 kLOC, 3 325 `#[test]`), read as source only. Ferrox's `README`, `AGENTS.md` and `docs/` were deliberately not used as evidence; where their comments contradict the code, the contradiction is recorded below. Xray semantics are checked against `thirdparty/Xray-core` in this checkout.

## 0. Why ferrox is worth reading at all

Its per-protocol code is real, and its differences from ours are informative in both directions: three of the four items below are **leas defects the Ferrox tree made visible**, and the fourth is a capability we deliberately lack. The transport/TLS halves of the same audit are separate specs; verification-methodology findings are in `2026-11-05-ferrox-derived-verification-gates-design.md`.

## 1. Witness verdicts

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| P1 | leas VMess sends `option = 0` — size field unmasked, no per-chunk padding | **CONFIRMED — wire-visible; framing itself is intact** | `crates/leas-native/src/protocol/vmess/header.rs:96` `body.push(0); // option (basic format; chunk-stream option is Task 6)`. Xray's client always sets `0x04\|0x08` for both AES and ChaCha bodies: `thirdparty/Xray-core/proxy/vmess/outbound/outbound.go:109-115`. **What option=0 actually costs is narrower than "unpadded body":** Xray's `AuthenticationReader` still parses `[2B size][AEAD payload]` (`common/crypto/auth.go:107-138`), so the record shape is right; with mask+pad it *also* SHAKE128-masks the 2-byte size field and subtracts a per-chunk random padding length before opening (`:126-132`, `:150-160`). Under option=0 leas writes that length in the clear — `crates/leas-native/src/protocol/vmess/stream.rs:443-444` `self.seal.splice(0..0, field.to_be_bytes())` with no mask pass. Ferrox implements both bits: `crates/ferrox-app/src/vmess.rs:433-505` (SHAKE128 pad then mask, that order), `:891-926`. `0x01` (`RequestOptionChunkStream`) is `[DEPRECATED 2023-06]` and must never be set — `common/protocol/headers.go:32-33`. |
| P2 | leas refuses `encryption=mlkem768x25519plus` together with a `flow` | **CONFIRMED — and the refusal is wrong** | `crates/leas-native/src/protocol/vless/mod.rs:79-83` returns `Config("flow cannot be combined with mlkem encryption")`. Xray parses `flow` and `encryption` from the **same user object** with no cross-check (`thirdparty/Xray-core/infra/conf/vless.go:329-378`), and the inbound side that would need the check does not have one — it only rejects `encryption` in *inbound* settings (`:84-86`), i.e. it is an outbound-only knob. Runtime proof that both apply: the encryption instance is built from the account and the handshake runs on the conn (`proxy/vless/outbound/outbound.go:84-96`, `:207-212`), then flow addons are added (`:240-241`) and the vision reader wraps the *decrypted* stream (`:379-391`). The decisive line is `:262-267`: `ob.CanSpliceCopy = 3` is set precisely because the conn is an `*encryption.CommonConn` — vision peels the encryption layer, not the outer TLS. Ferrox composes the same two: `crates/ferrox-core/src/vless_encryption.rs:1466-1472` + `vision.rs:466-500`. |
| P3 | leas treats a non-zero VLESS response version as payload passthrough | **CONFIRMED — deliberate, and its stated reason does not hold** | `crates/leas-native/src/protocol/vless/stream.rs:140-151` sets `PeelState::Done`, `PeelAck::NotApplicable`, hands the byte to the caller, citing "the REALITY transparent-proxy fallback". Xray errors: `proxy/vless/encoding/encoding.go` `DecodeResponseHeader` rejects an unexpected version. The named fallback cannot reach this code: an unauthorised REALITY client completes its handshake against the **cover site's** certificate, and `crates/leas-tls/src/reality/verify.rs` rejects that cert before the VLESS peel ever runs. |
| P4 | leas has no Shadowsocks-2022 extensible identity header (EIH) | **CONFIRMED — deliberate** | `crates/leas-native/src/protocol/ss/stream2022.rs:34-35` "There is no extensible identity header: single-user PSK only." Ferrox implements the master→user chain for TCP and UDP: `crates/ferrox-core/src/shadowsocks2022.rs:102-193`, dial `:609-650`, UDP `seal_list` `:1480-1515`. |
| P5 | leas vision latches passthrough on the first ≥21-byte non-UUID chunk | **CONFIRMED — but deliberate and defensible; keep it** | `crates/leas-native/src/protocol/vless/vision.rs:733-742` with the rationale at `:709-731`. Xray re-checks the initial state per block (`proxy/vless/outbound/outbound.go` vision filter), so the behaviours differ only for a peer that writes a ≥21-byte non-UUID chunk *before* its UUID — which cannot be a vision peer. Recorded as an intentional divergence with a test, not a defect. |
| P6 | leas response-header peel skips addons; ferrox refuses any non-zero `addon_len` | **leas is correct; ferrox is buggy** | leas bounds addons and consumes them: `crates/leas-native/src/protocol/vless/stream.rs:179-195`. Ferrox's callers always hand its decoder a 2-byte head, so a real addon body is refused (`ferrox-core/src/vless.rs:380-391`; callers `vision.rs:510-527`, `proxy.rs:16923`) — its own `if consumed > 2` recovery branch is dead code (`proxy.rs:29808-29811`). |
| P7 | leas VLESS `encryption` wire is real (ML-KEM-768 + X25519, sealed-record tunnel) | **CONFIRMED both sides; ferrox's is a faithful port** | leas: `protocol/vless/encryption/`; roster of config spellings and ChaCha-only client, per `docs/reference/native-core.md` VLESS row. Ferrox: grammar `mlkem768x25519plus.<native\|xorpub\|random>.<1rtt\|0rtt>.<pad>.<key>`, relay chain, BLAKE3 derive-key, AES-GCM-or-ChaCha selection — `ferrox-core/src/vless_encryption.rs:262-300`, `600-700`, `1838-1846`, `76-96`. |
| P8 | leas always seals with ChaCha20-Poly1305; Xray picks AES-GCM on AES-capable hosts — an **interop break** | **REFUTED. Fidelity only.** | The cipher is self-describing per direction, not negotiated: Xray's client takes `protocol.HasAESGCMHardwareSupport` as a *local* flag (`thirdparty/Xray-core/proxy/vless/encryption/client.go:69`, `common.go:157-164`), and the server does not require it — on an open failure it flips its own `UseAES` and retries the other cipher (`server.go:186-189`), then carries that choice into both AEADs (`server.go:229-267`). leas's fixed ChaCha (`encryption/mlkem.rs:100`, `:108`) is therefore accepted by an Xray server and accepts an Xray client. leas already documents the deviation it *does* have — `0rtt` accounts run the full 1-RTT handshake and the issued ticket is never replayed (`mlkem.rs:28-29`). |

## 2. Defects and gaps, ranked by wire consequence

| Rank | Item | Consequence | Class |
|---|---|---|---|
| 1 | **VMess `option = 0`** (P1) | Every real VMess client masks and pads. Ours sends a **clear 2-byte size field and no per-chunk padding** — the record shape is valid, so this is not a framing bug, but the length signal is exposed and the padding that blunts length analysis is absent. A DPI signature that matches no client in the wild; the reason `Task 6` exists at all. | fingerprint + traffic analysis |
| 2 | **`encryption` + `flow` refused** (P2) | A share link carrying both is a legal Xray configuration that we reject at connect. This is a hard interop failure for that class of server config, not a fidelity blemish. | interop |
| 3 | **Non-zero response version is passthrough** (P3) | A wrong endpoint (or a mis-signatured server) is delivered to the application as payload instead of an error. Silent corruption, no diagnostic. | error masking |
| 4 | **No SS2022 EIH** (P4) | Cannot dial a multi-identity SS2022 relay at all. Client-side value is limited to relay/detour topologies; a plain single-user PSK server is unaffected. | capability |

## 3. Errata — ferrox behaviours NOT to copy

Recorded so a later slice does not "restore parity" with a bug.

| Item | Evidence | Why not |
|---|---|---|
| VMess inbound **requires** `RequestOptionChunkStream` (`& 0x01`) | `ferrox-app/src/vmess.rs:1497`; Xray marks that bit DEPRECATED and derives stream/packet from the command (`common/protocol/headers.go:21-35`) | Rejects valid peers, including ours. |
| VMess `security = NONE` accepted server-side | `ferrox-app/src/vmess.rs:68-72`, `606-628`; Xray refuses every non-AES/ChaCha body (`proxy/vmess/encoding/server.go:325-328`) | Unauthenticated body mode that no upstream peer accepts. |
| Protocol parsers resolve domains via DNS | `vmess.rs:724-740`, `proxy.rs:30015-30019`, `shadowsocks2022.rs:1928-1930` | Attacker-controlled DNS work on the handshake path; also destroys domain-based routing. leas keeps `TargetAddr` to the dialer — keep it. |
| SS2022 UDP server: one upstream socket + `dest→client` map | `shadowsocks2022.rs:2114-2150`, `2185-2207` | Two clients to the same destination get each other's replies. leas's per-session model (`protocol/ss/udp.rs:531-647`) is correct. |
| SS2022 session table without TTL | `shadowsocks2022.rs:1380-1400` | Unbounded growth from an authenticated peer; Xray uses a 500 s UDP session manager. |
| Trojan mux interception inside the address parser | `proxy.rs:29933-30014` | Xray does it at dispatch (`common/mux/server.go:41-45`). leas keeps mux in its own module. |

## 4. Decisions

- **D1 — VMess masking/padding is adopted in full** (`0x04` mask + `0x08` pad), with the SHAKE128 draw order **pad first, then mask** as both Xray (`common/crypto/auth.go:127-132`, `240-265`) and ferrox (`vmess.rs:433-505`) do. Authenticated length (`0x10`) stays **out**: it changes the length-record path on both sides for no measured gain, and no mainstream client sets it by default. `0x01` (`RequestOptionChunkStream`) is **never** set — it is `[DEPRECATED 2023-06]` (`common/protocol/headers.go:32-33`), and a peer that *requires* it (ferrox does, `vmess.rs:1497`) is the non-conforming side. The `security` byte continues to select AES-GCM vs ChaCha20-*only*; `NONE` remains unimplemented (we never emitted it).
- **D2 — lift the `encryption`+`flow` guard.** Compose vision over the sealed layer exactly as Xray does: `ob.CanSpliceCopy = 3` is set specifically because the conn is an `*encryption.CommonConn` (`thirdparty/Xray-core/proxy/vless/outbound/outbound.go:262-267`), i.e. the Direct handoff peels the **encryption** record layer and leaves the outer TLS session intact. That line is the authority for this decision; ferrox reaches the same composition (`vless_encryption.rs:1466-1472`, `vision.rs:466-500`). This is the largest single-wire change in this spec and needs its own slice and e2e row (S3).
- **D3 — a non-zero response version is an error.** `NativeError`/`io::Error` with the byte preserved in the message. If a future REALITY-fallback mode needs passthrough, it gets an explicit flag set by the engine, not a heuristic on a response byte.
- **D4 — SS2022 EIH is deferred, not dropped.** The config surface (`leas-proto` SsConfig) carries one PSK string; EIH needs an identity list, so adopting it is a proto change (§"`leas-proto` is changed only deliberately"). Defer until a relay/detour topology asks for it; record the reason in the SS2022 module header so the current single-user state reads as a decision.
- **D5 — keep the vision UUID latch.** Add the missing test that pins it (first chunk < 21 bytes → still matching; ≥ 21-byte mismatch → passthrough for the rest of the stream).
- **D6 — keep ChaCha20-Poly1305; AES-GCM selection is a parity probe, never an interop fix** (P8). If it is added at all, it is a runtime CPU probe mirroring `HasAESGCMHardwareSupport` plus a test that the server accepts either — never a "fix" ticket, and never a reason to touch the record path. The genuinely unimplemented parts stay recorded as such: `0rtt` ticket replay and the server's `MaxNonce` re-key run; both are wire-valid without them (`encryption/mlkem.rs:28-29`).

## 5. Slices (each independently shippable, in risk order)

| Slice | Change | Gate |
|---|---|---|
| **S1** | VMess `option` byte: emit `0x04\|0x08`, implement SHAKE128 pad + mask on the body keyed by the existing session key/IV | New unit rows: pad-then-mask order; a Go-derived byte vector for a fixed key/IV/body (Xray's own `common/crypto/auth.go` path); round-trip against the existing decoder with the bits set. Tier-3 e2e row against a real xray-core server (VMess e2e already exists). |
| **S2** | Response-version error (D3) + the vision-latch test (D5) | Byte-level: a fake server returning `0x01` must surface an error, not payload. Existing vision tests must stay green. |
| **S3** | `encryption` + `vision` composition (D2) | e2e: `encryption=mlkem768x25519plus.native.<s>.…&flow=xtls-rprx-vision` against xray-core; assert the Direct handoff happens on the encryption layer and the outer TLS records stop being re-framed. |
| **S4** | (deferred) SS2022 EIH | n/a until a proto decision exists. |

## 6. Non-goals

- **`VisionSeal`/`VisionOpen`-style duplicate framing** (`ferrox-core/src/vless.rs:598-800`) — production-dead in ferrox; we keep one codec.
- **A VLESS reverse-portal command (`cmd 4`)** and any server-role work. leas is a client.
- **An SS2022 identity-list proto**, until a relay topology asks for it (D4).

### Owner decisions that *left* this file (2026-11-05)

Recorded so they are not re-argued:

- **VMess legacy `alterId` is IN, as an opt-in dial path** (plan T6). The earlier "dead protocol" verdict was wrong for our scope: `thirdparty/v2ray-core-legacy/proxy/vmess/encoding/client.go:76-127` implements the non-AEAD header (id-hash + AES-128-CFB), and sing-box still threads `AlterId` (`sing-box/protocol/vmess/outbound.go:106` via `sing-vmess`). Only Xray-core dropped it. The delta is one header cipher and an MD5 id chain, on a path nobody reaches unless `alter_id > 0`.
- **Micro-optimisations are IN, measured-only** (plan T14): the vision gathered write and in-place reader are kept only if `just bench` shows ≥5% on that path; otherwise reverted with the measurement recorded here.

## 7. Verification plan

- Every wire claim above is already anchored to a `path:line`; S1 additionally requires a **Go-derived** vector, not a Rust round-trip (self-consistency is what hid the `option = 0` gap).
- S3's acceptance is a real xray-core handshake; a hermetic fake is insufficient because the defect is *composition order*, which a fake that we wrote will agree with.
- No test is deleted by this spec.
