# `leas-tls` review hardening — verified plan

**Status:** EXECUTED 2026-11-02 — S1, S2, S3, S4 landed; S2b closed by existing evidence; S5 landed with a reduced split (see Execution notes).
**Origin:** Grok 4.7 review of `leas-tls` (pasted 2026-11-02), re-checked against
`native-core-stub` @ `bb416a1`. Every claim below was re-verified in the tree;
claims the review got wrong, under-specified, or missed are called out.

Workspace policy is unchanged and not up for renegotiation: ring only,
`#![forbid(unsafe_code)]`, `zeroize` on owned key material, pure-Rust `ml-kem`,
no new crypto backends. Crate version is `0.1.0`, so a documented public-API
change is cheap; the seams (`ServerVerifier`, `HelloProvisioner`,
`SecureRandom`, `Stream`) stay.

## 0. Authority reconciliation

The review is a claim set, not the authority. Each slice is checked against the
standing decisions, and where this plan departs from the review's *ordering* it
says so:

| Authority | Binding statement | How this plan honours it |
|---|---|---|
| `docs/architecture/decisions.md` § Native core & TLS | "TLS fingerprint engine is ring-only: TLS 1.3 + a 1.2 fallback, declarative browser-hello profiles, WebPKI verification (`insecure`/`pin_sha256` only), REALITY reuses the same hello machinery" | D5 (no deps), S1/S2 change no trust mode and no profile bytes; T6's replay is exactly "REALITY reuses the same hello machinery" applied to a second ClientHello |
| same | "Both crypto crates are `#![forbid(unsafe_code)]`"; secrets wiped | no `unsafe`; T10 keeps app traffic secrets in `Zeroizing` and *moves* them |
| same | Verification tiers: tier 1 offline hermetic (the CI gate), tier 2 live grader, tier 3 real-core e2e | S2's retry test is a hermetic scripted server; `probe_host`/grader rows are tier-2 evidence only, never gate |
| `docs/reference/native-core.md:177-181` | the engine "has no HRR retry and rejects the HRR a hybrid-unaware server sends"; 36/71 amiabot rows HRR-limited | T9 corrects that sentence to what it can support (M6); the plan never claims 36/71 recovery |
| `docs/reference/native-core.md` leas-tls crate map | `client` row: "`TlsConfig { mode, server_name, alpn, rng }` + one `connect()`"; `reality` row: "`SpiderConfig` + `spider.rs`" | D1 keeps `connect()` as the single entry and defers the spider move, so the documented map stays true in both the interim and after the move |
| `docs/aegis/adr/0007` | cryptographic dependency posture; hazmat governance | T10's `"traffic upd"` derivation stays inside `KeySchedule`, no new primitive |

Deviation from the review's phase order, stated once: the review puts the
spider move in Phase 1 and KeyUpdate in Phase 5. This plan moves the spider to
last (its fix needs a return type the review does not propose, see D1) and
KeyUpdate up to S3 (it is a live tunnel failure, not polish). Nothing else in
the review's ordering is changed.

## 1. Claim ledger

| # | Review claim | Verdict | Evidence |
|---|---|---|---|
| 1 | HRR is a hard failure | **true, worse than stated** | magic check runs *after* extension parsing, so a real HRR (which carries a 2-byte `key_share` hint) dies as `"ServerHello key_share extension too short"` — a generic `Handshake` error, never reaching the typed variant (`handshake/mod.rs:667-677` vs `:726-729`). The only HRR test uses a hint-less, session-id-less HRR (`:1337-1370`), which is why this passes. Justification is protocol correctness, **not** roster recovery: the roster's 36 failures are the ECH-grease rows (M6). |
| 2 | `SpecProvisioner::from(&Fingerprint)` can panic | **true** | `reality/mod.rs:153`. Also resolves the fingerprint **twice per connect** (`offers_hybrid_key_share` + `provision`, `:182-193`), each re-cloning the spec. |
| 3 | Spider-X belongs outside the engine | **true on layering, wrong on the fix** | `reality/mod.rs:341-345` calls `tokio::spawn` on the live `TlsStream` and returns `Err`. `connect()` returns `Result<TlsStream<S>>`, so "engine surfaces the error, caller runs the spider" needs a *new return shape*; `leas-native`'s `wrap()` can also only return one value. The real defect is that the engine — otherwise runtime-agnostic — requires a Tokio runtime and takes ownership of a stream the caller cannot cancel. |
| 4 | `handshake/mod.rs` is monolithic | **true but oversold** | 2,433 lines = 1,190 source + 1,242 tests. Splitting is maintenance, not correctness. |
| 5 | Transcript is a growing `Vec<u8>` | **true, and the fix is smaller than the review thinks** | `crypto/mod.rs:238-289` keeps `Vec<u8>` and rehashes it on every `transcript_hash()`. Both consumers only ever want `Hash(transcript)`: `verify/mod.rs:198` hashes `signed_data` itself, `reality/verify.rs` likewise. So `transcript_bytes()` can disappear entirely rather than being "kept as a bounded prefix". |
| 6 | No session resumption | **true** | `record/stream.rs:539` skips `NewSessionTicket`. Deferred below with a measurement gate, not a plan item. |
| 7 | No KeyUpdate | **true, and it is a live bug, not polish** | `record/stream.rs:537-549` errors on any handshake message other than NST ⇒ a peer's `KeyUpdate` kills the tunnel. A Go/rustls peer sends one at the RFC 8446 §5.5 limit (~2^24.5 records ≈ 24 GB per key), which a long-lived tunnel reaches in tens of minutes at sustained throughput. |
| 8 | ALPN validated as UTF-8 at connect | **true, and the fix deletes code** | `client.rs:121-135` bytes→`&str`; `spec/mod.rs:560` takes `&[&str]`. ALPN ids are opaque bytes (RFC 7301 §3.1). `TlsConfig.alpn` is *already* `Vec<Vec<u8>>`. |
| 9 | `TlsConfig.curves` ignored by REALITY | **true, intentional** | documented at `client.rs:55-56`; the provisioner owns the hello shape. Doc-only. |
| 10 | `FixedChrome130Hybrid` is misnamed | **true** | `reality/mod.rs:128-136` serves `chrome_130` + the hybrid share. |
| 11 | Post-handshake behaviour undefined | **true** | `record/stream.rs:537-549`: NST skipped, everything else fatal, no doc. Direct mode (`read_direct`/`write_direct`) bypasses the record layer entirely, so the policy must state that too. |

## 2. Defects the review missed

**M1 — REALITY + `compress_certificate` divergence.** `reality/mod.rs:331` passes
`offered_compress: &[]` to `drive`, on the premise that the REALITY hello offers
no compression. That premise is false for the path `leas-native` actually takes:
`SpecProvisioner::from(&Fingerprint)` resolves a *generated* profile, and 10 of
the 19 generated Chrome rows offer `compress[brotli, zstd]`
(`profiles/generated/chrome.rs`, e.g. `:256`). A REALITY server that compresses the
Certificate is then rejected with `"server compressed the Certificate with
algorithm 0x0002, which the ClientHello did not offer"`
(`handshake/mod.rs:1086-1090`) — a false claim about our own hello.
Fix: derive the offered list from the hello bytes (`client_hello_extension(hello, 0x001B)`),
which also deletes `drive`'s parameter and the plain-path derivation
(`handshake/mod.rs:414-420`).

**M2 — `drive` duplicates what the hello already says.** `offered_session_id`
is passed separately from `hello` although `BuiltHello::session_id()` reads it
from the same bytes. Folding both derivations into `drive` removes two
parameters and a whole class of drift (M1 is exactly that class).

**M3 — RFC 8446 §4.4.1 transcript on retry.** The review's HRR plan says
"rebuild the ClientHello consistently" but not the *message_hash* step: the
post-retry transcript is `message_hash(254, Hash(ClientHello1)) ‖ ClientHello2 ‖
ServerHello2 ‖ …`. Retrying without it produces a `Finished` the server rejects —
a failure that only shows against a real HRR server.

**M4 — ClientHello2 is not a rebuild, it is a replay.** `build_hello` draws from
`params.rng` throughout: the GREASE pair, the ECH grease triple, the client
random, the `Random32` session id, and **one fresh value per further GREASE
placeholder** (`hello/mod.rs:64-200`, `draw_grease_distinct`). So a naive
re-provision emits a different random, a different GREASE layout and a different
session id. RFC 8446 §4.1.2/§4.1.4 ("same except `key_share`, `cookie`,
`early_data`, padding") and REALITY's auth key (`HKDF(shared, client_random[..20])`)
both require the CH1 values to be replayed. `RuntimeValues` alone is *not* the
seam the review assumes — it carries `grease_a`/`grease_b` only, while the
per-placeholder draws happen inside `build_hello` from the RNG. Replaying the
draw stream (T6) is the minimal seam that keeps every byte.

**M5 — no confidentiality limit.** `advance_seq` (`record/stream.rs:89-98`)
refuses a `u64` wrap, so there is no nonce reuse, but nothing enforces the
RFC 8446 §5.5 per-key limits that motivate KeyUpdate.

**M6 — the roster's 36 failures are the ECH-grease rows, not HRR.**
`docs/research/amiabot-roster-report.md:26-29` attributes them to "the engine
rejects HRR". Cross-tabulating the report's own 71 per-profile rows against the
spec each name compiles to gives a clean split:

| spec attribute | failing rows (36) | passing rows (35) |
|---|---|---|
| `encrypted_client_hello` (ECH grease) offered | **36** | **0** |
| `compress_certificate` offered | 35 | 12 |
| hybrid `key_share` (`mlkem768, x25519`) | 10 | 9 |
| `key_share[x25519]` only | 26 | 26 |

No failing row lacks ECH and no passing row has it, while the hybrid key share
is present on both sides (9 passing rows send it) — so HRR is *not* the
discriminator, and the observed `alert 50` comes from the server rejecting our
hello, not from us rejecting a retry. HRR retry remains a real protocol gap
(D2/T4-T8) but must not be credited with these rows. The ECH extension's wire
layout looks conformant on inspection (`spec/mod.rs:435-456` matches RFC 9849
§5.1: type, `kdf_id‖aead_id`, `config_id`, `enc<0..2^16-1>`,
`payload<0..2^16-1>`), so the cause is unproven and needs the S2b experiment
rather than a guess. Correct the report sentence (T9) and never sell HRR as
"roster goes green" (D6).

## 3. Decisions

**D1 — Spider stays in `leas-tls` for now; the move is the last slice.**
It is a layering defect with no user-visible failure, it costs a public return
type, a `leas-native` phase change and e2e rewrites, and `connect` cannot hand
back the stream today. Interim: document that `connect_reality` requires a Tokio
runtime (already de-facto true) so the coupling is stated, not implicit.
The move, when it happens: `client::connect_outcome(stream, &config) ->
Result<ConnectOutcome<S>>` with `ConnectOutcome::{Tls, RealityFallback}(TlsStream<S>)`;
`connect()` becomes the 5-line wrapper that drops the stream and returns
`Err(RealityFallback)`; `reality::spider` + `SpiderConfig` move to
`leas-native`'s transport phase. No shim, no duplicate path.

**D2 — HRR retry is plain-TLS only.** REALITY's HRR would need the sealed
session id re-sealed over CH2's AAD (the seal covers the hello with the slot
zeroed, and CH2 differs), and xray-core's REALITY transport has no HRR path of
its own (no `HelloRetry`/`KeyUpdate` occurrence in its Go source — it delegates
the handshake to `crypto/tls`, which cannot re-seal our session id). Under
`ServerAuth::Reality` an HRR stays a typed error. Recorded as an explicit
non-goal in the code comment and `native-core.md`.

**D3 — Session resumption deferred, behind a measurement.** REALITY cannot
resume (the legacy session id *is* the auth payload), so only plain TLS
qualifies; the only repeated dial of one endpoint in this app is Fast→Real on
the same link. Add a counter (handshakes vs. distinct endpoints) in the batch
pipeline; plan resumption only if the ratio justifies a ticket store, PSK
binders, and a new persisted-secret surface.

**D4 — KeyUpdate is receive-first.** Receiving + ACKing removes the live
failure; sending is added only together with the §5.5 limit guard (M5), because
sending without enforcing a limit is cosmetics.

**D5 — No new dependencies.** Everything above is ring/owned-buffer work.
`ring::digest::Context` replaces the transcript `Vec`; no HKDF primitive is
needed for KeyUpdate (`KeySchedule`-owned derivation is reused).

**D6 — Correct the roster report's HRR attribution** when HRR lands; do not
retrofit a success claim onto rows that never produced evidence.

## 4. Slices

Order is dependency order, not severity order: S1 is prerequisite-free, S2b is
an independent experiment that can run first, S2 is the only wire-level
correctness win, S3/S4 are independent, S5 is mechanical.

**T0 — Record the gate state.** `just quality-gate code` at HEAD, recorded in
this plan's execution notes. Do not assume green: ADR 0011 already records a
pre-existing clippy red outside its change. `cargo clippy -p leas-tls` is a trap
(AGENTS.md) — the workspace form is the only evidence.

### S1 — typed configuration surface (no wire change)

- **T1 `SpecProvisioner` fallible + resolved once.** `TryFrom<&Fingerprint>` →
  `Result<SpecProvisioner, TlsError>`; resolve in the constructor, hold
  `Arc<ClientHelloSpec>`, delete `From`. Callers: `client.rs` docs,
  `leas-native/src/security/mod.rs:94-106`,
  `leas-native/src/security/reality.rs:18` (re-export).
  Native maps the error to `NativeError::Config` — an unresolvable fingerprint
  is a config defect (`FailureEvidence::ConfigDefect`), never a server verdict;
  that keeps it out of `RealityFallback` purging.
  *Test (as shipped — the closure is gone, so the resolve-count assertion is
  meaningless):* `#[rstest]` over resolvable / unknown identity, where the
  unknown case (`Fingerprint::new(Browser::Chrome).with_version(200)`) must
  return `Err` at CONSTRUCTION instead of panicking inside `provision`; plus a
  regression pin that `offers_hybrid_key_share()` agrees with the key_share of
  the hello `provision` builds (they can no longer diverge — the spec is held,
  not re-resolved).
- **T2 ALPN as bytes.** `BuildParams.alpn: Option<&[&[u8]]>`,
  `encode_alpn_override_into(&[&[u8]])`; spec-owned `ExtensionSpec::Alpn(Vec<String>)`
  encodes through the same helper via `as_bytes()`. Delete `client.rs:121-135`.
  *Test:* `#[rstest]` table: `["h2", "http/1.1"]` (unchanged bytes), a single
  `[0xFF, 0x00]` entry (now accepted, exact wire bytes), an empty list
  (extension encodes `0`-length list — decide and pin whichever the builder
  already does), an over-long entry (> 255 bytes) → `Spec` error.
- **T3 rename `FixedChrome130Hybrid` → `FixedChrome130Hybrid`.** Sites:
  `reality/mod.rs:128/198`, `reality/messages.rs:97/171/219`,
  `leas-native/{security/mod.rs:24/94/104, security/reality.rs:18/24/31/136, context.rs:32/71}`, docs.
  No alias, no deprecation shim.
  *Test:* the existing `Debug` pin in `security/reality.rs:136` is the only
  assertion that must change; behaviour tests are untouched.

**Acceptance S1:** `cargo nextest run -p leas-tls -p leas-native --all-features`
green; the generated-profile JA4 gate unchanged (`tests/generated_ja4_gate.rs`).

### S2 — HelloRetryRequest (the only wire-level fix)

TDD-strict for this slice: T4/T6/T7 write the failing tests first (the
hint-bearing HRR row is red on `bb416a1` for the reason in claim 1), then the
implementation. Do not add a test that passes on the old code to "cover" the
retry.

- **T4 detect HRR before parsing extensions.** In `parse_server_hello`, compare
  `random == HRR_RANDOM` immediately after `body[2..34]`; return
  `ParsedServerHello::Hrr { selected_group: Option<u16>, cookie: Option<Vec<u8>> }`
  (or an enum split). HRR-specific extension parsing:
  `key_share` carries **only** `selected_group(2)` (RFC 8446 §4.2.8.2), so the
  current `ext_data.len() < 4` guard must not apply; `cookie` (0x002C) is
  `opaque<1..2^16-1>`. Keep the session-id echo check for HRR (§4.1.4 requires
  it too).
  *Test:* `#[rstest]` over: HRR with `key_share` hint only; HRR with
  `key_share` + cookie; HRR with neither; a *non*-HRR `ServerHello` whose
  `key_share` is 2 bytes (must stay an error). Each asserts the parsed variant,
  and the hint-bearing cases are the regression that the current code fails.
- **T5 retry policy, one attempt.** Retry iff `selected_group` was in the
  offered `supported_groups` **and** the engine can produce a share for it:
  `X25519` (0x001D) or `X25519MLKEM768` (0x11EC). Otherwise return
  `TlsError::HelloRetryRequest` with the group and the reason in the message
  (keep the variant — `leas-native` and purge code already key off types, and a
  new variant would need a `map_tls_err` arm for no gain). Second HRR → error.
  Hybrid requested but not offered on CH1 → generate the ML-KEM keypair at
  retry time (the connector skips keygen for classical-only profiles,
  `reality/mod.rs:275-284`; the plain path does the same at `handshake/mod.rs:394-399`).
- **T6 replay-based CH2 (draw-stream replay).** Do **not** split
  `RuntimeValues` out of `build_hello`: the per-placeholder GREASE draws and the
  random/session-id draws are the state that must survive, and they are RNG
  reads. Instead add two tiny adapters over the existing `SecureRandom` seam
  (`SecureRandom::fill` takes `&self`, so interior mutability is required — `Mutex`,
  std only, no new dependency):
  - `hello::RecordingRng<'a> { inner: &'a dyn SecureRandom, log: Mutex<Vec<u8>> }`
    — CH1 is built through it; every byte handed to the builder is kept.
  - `hello::ReplayRng<'a> { log: &'a [u8], cursor: Mutex<usize> }` — CH2 is
    built through it; it yields the recorded bytes in order and returns
    `TlsError::Handshake("hello replay diverged …")` when the builder asks for
    more (or the stream ends mid-draw). Silent fresh randomness would defeat the
    whole point, so divergence must be a hard error.
  Retry = `ReplayRng` + a `ClientHelloSpec` clone whose `KeyShare` is the single
  selected group + a cookie extension appended. Add
  `ExtensionSpec::Cookie(Vec<u8>)` (0x002C) — there is no variant today. The
  record `padding` recomputes against the 512-byte target from the new unpadded
  length, which is what a browser does too (and is explicitly allowed by
  §4.1.2).
  *Test (pure, no I/O):* build CH1 through the recorder, CH2 through the replay,
  parse both with `parse_hello`, and assert (a) random, session id, cipher
  order, extension order and every extension except `key_share` byte-identical,
  (b) `cookie` present with the server's bytes, (c) CH2's `key_share` holds
  exactly the selected group and nothing else, (d) with a small cookie the
  final record is still 512 bytes, (e) a replay stream truncated by one byte
  produces the divergence error, not a hello. This is the fingerprint-drift
  guard.
- **T7 transcript across the retry.** `KeySchedule::add_transcript(&make_hs_msg(0xFE, &hash_ch1))`
  (3-byte length = hash length) before CH2 (RFC 8446 §4.4.1). `hash_ch1` must be
  computed over CH1 **before** the message_hash is added.
  *Test:* RFC 8446 §4.4.1 vector for the synthetic message; plus a unit test
  that `message_hash ‖ CH2 ‖ SH2` hashes to the same value as a reference built
  by hand.
- **T8 end-to-end retry.** Scripted duplex server: HRR(hint = 0x11EC, cookie) →
  assert on the wire that CH2 is the expected shape → then send a plain-TLS
  handshake continue path or close, asserting the *specific* resulting error
  (not "some error"). If a rustls server with a ring provider can be configured
  to prefer X25519MLKEM768 (verify at implementation time), add an interop row
  that completes a full handshake through the retry; if not, record why in the
  test comment instead of faking it.
- **T9 docs.** `native-core.md` leas-tls row: HRR (one retry, `key_share` +
  `cookie`, plain TLS only), the `client/` row's `TlsConfig` spelling is missing
  `curves` (claim 9's doc half), and the `reality/` row after T3's rename;
  amend `amiabot-roster-report.md`'s HRR sentence per D6.

**Acceptance S2:** the plain-path interop test still green; the new scripted
HRR test fails on `bb416a1` and passes after; `probe_host` against a
Cloudflare-fronted host reports the same or a *newly successful* outcome, with
the observation recorded honestly (no claim about the 36 `alert 50` rows).

### S2b — the roster ECH discriminator (independent of S2, can run first)

The user's recollection was "HRR makes the roster fail"; the report's own rows
say the failing 36 are exactly the ECH-grease shapes (M6). This slice is one
decisive experiment plus the decision it forces, and it is cheap enough to run
before S2.

- **T15 repro, no library change.** The sweep already strips one extension:
  `crates/leas-native/examples/amiabot_sweep.rs:242`
  (`retain(|e| !matches!(e, ExtensionSpec::CompressCertificate(_)))`). Add the
  ECH case beside it (`!matches!(e, ExtensionSpec::EchGrease)`) behind an
  `--strip-ech`/env switch, then run the sweep twice and diff the per-profile
  flags: `chrome_143_windows_desktop` (failing) and `chrome_130` (passing) are
  the anchors.
  *Acceptance:* a recorded before/after table. If stripping ECH turns 36
  `alert 50` rows green, the discriminator is confirmed as *ours*, not HRR's;
  if it does not, M6's correlation is confounded and the plan says so instead
  of shipping a fix on a coincidence.
- **T16 audit the ECH grease wire.** `encode_ech_grease_into`
  (`spec/mod.rs:435-456`) matches RFC 9849 §5.1 field-for-field on inspection,
  so compare against what a real Chrome actually sent: the roster's `obs=` byte
  counts and the JA4 pins do not capture it, so this needs either a captured
  hello (any real browser trace) or a byte-diff against `boringssl`'s
  `MakeGreaseEncryptedClientHello` output shape. Decide one of three outcomes,
  in this order of preference:
  1. **encoder defect** → fix the bytes (fingerprint fidelity is the point);
  2. **valid grease the peer rejects** → strip ECH in sweeps only, with the
     cause recorded, and keep the extension in production hellos;
  3. **inconclusive** → leave the wire alone, record the open question, and
     drop the "roster goes green" claim.
  *Test:* a golden byte-vector unit test for the chosen shape (the encoder has
  one at `spec/mod.rs:592-617` today; extend it with the field order RFC 9849
  names so a future edit cannot reshuffle it silently).
- **T17 re-run the tier-2 sweep** after the decision, and record it honestly:
  `--roster` grader (71/71 expected, no network gate) plus the amiabot sweep if
  the host's IP reputation allows it. Tier-2 evidence only — never a CI gate
  (decisions.md verification tiers).

**Acceptance S2b:** a written disposition (fix / strip-in-sweeps / inconclusive)
backed by the T15 table, and `amiabot-roster-report.md` updated to whatever the
measurement supports.

**Execution disposition (2026-11-02): closed WITHOUT running T15.** The
disposition came from in-tree evidence instead of a new experiment:
`docs/reference/native-core.md` ("What tier 1's roster gate cannot see")
already records the 0-byte `encrypted_client_hello` body these rows shipped and
its fix (`profiles::tests::every_roster_hello_has_rfc_minimal_extension_bodies`,
`tests/strict_peer_presets.rs`), and the M6 cross-tabulation reproduces the ECH
correlation on the report's own rows. T15/T16/T17 are therefore not
checkboxed-done: T15 is unnecessary, T16's encoder audit is satisfied by the
RFC-minimal-body gate that now exists, and T17 (a live sweep) is the only open
item — it needs network and is not a gate. The report carries the correction.

### S3 — post-handshake correctness

- **T10 receive `KeyUpdate`.** `TlsStream` gains
  `AppSecrets { suite, client, server }` (`Zeroizing`, hash-len bytes each) so
  the read key can be rotated: `server = HKDF-Expand-Label(server, "traffic upd", "", len)`
  and a fresh `AeadKey`; `read_seq` resets to 0. Two concrete blockers to fold
  in, both visible in the tree today: `tls13_label` is a **closed** match
  (`crypto/mod.rs:250-259`) and needs the `"traffic upd"` arm, and `AppSecrets`
  must be *moved* out of the handshake, not cloned (a duplicated secret is a
  second key-update stream that can silently desynchronise). `post_handshake_message`
  becomes a parse of `KeyUpdate{request_update}` (type 24) and the read loop
  performs the rotation; when `request_update == 1` the stream queues one
  `KeyUpdate(update_not_requested)` record (write key unchanged). TLS 1.2:
  unchanged (type 24 is illegal there — keep it fatal).
  *Test:* `#[rstest]` rows: `update_not_requested` (data after rotation reads
  correctly, no ACK), `update_requested` (ACK emitted exactly once, data after
  rotation reads correctly), unknown handshake type (fatal, unchanged), NST
  (skipped, unchanged). Records are built with the existing crypto helpers, as
  `new_session_ticket_records_are_skipped` already does.
- **T11 send `KeyUpdate` + §5.5 limit guard.** Track sealed-record counts;
  at the suite's limit (AES-GCM 2^24.5, ChaCha20-Poly1305 2^25 records) seal a
  `KeyUpdate(update_requested)` with the *current* write key, then rotate `write`
  and reset `write_seq`. Disabled in direct mode (no record layer).
  *Test:* the limit is a private const per suite; the decision is a pure
  `fn should_update(seq, suite) -> bool` unit-tested at limit-1 / limit /
  limit+1, and one stream-level row drives the existing `pub(crate)` rotation
  helper directly (no test-only knob reaches the public API, and no test emits
  16 million records).
- **T12 policy doc on `TlsStream`.** One comment block: NST → discarded
  (resumption not implemented, D3), KeyUpdate → handled, other handshake
  messages → fatal, alerts → `close_notify` = EOF / otherwise
  `ConnectionReset`, and **direct mode bypasses this entire policy** (the Vision
  splice hands the socket to the tunnel). Also expose the negotiated ALPN from
  `EncryptedExtensions` instead of discarding it (`handshake/mod.rs:935-1014`
  validates then drops it) — one accessor, no wire change.

**Acceptance S3:** a `TlsStream` that has consumed a peer `KeyUpdate` keeps
serving plaintext; before the change the same bytes surface
`"unexpected handshake message type 24"`.

### S4 — streaming transcript

- **T13** `KeySchedule.transcript: ring::digest::Context`; keep
  `transcript_hash()`'s signature; delete `transcript_bytes()`. `VerifyContext`
  carries `SignedData::{Tls13Hash(&[u8]), Tls12Raw(&[u8])}` (the TLS 1.2 arm
  keeps today's `tls12.rs:316-331` bytes); `verify/mod.rs:198` and
  `reality::verify` take the hash instead of hashing again.
  Two API facts that decide the shape, both checked in the vendored source:
  - **`ring::digest::Context` is `Clone`** (`ring-0.17.14/src/digest.rs:186`,
    `#[derive(Clone)]`) but `finish(self)` consumes (:260). So a checkpoint is
    `self.ctx.clone().finish()` — O(state ≈ 200 B), not O(transcript), which is
    what makes `transcript_hash(&self)` work *mid-schedule* at all four call
    sites (`derive_secret` :408, `finished_key`, `finished_mac`, and the
    auth-boundary `transcript_bytes()` replacement). Verify the `Clone` derive
    survives future ring bumps; if it ever disappears, the fallback is a
    `Vec`-accumulator beside the Context, and this task gets re-scoped rather
    than hand-rolling a hash.
  - **`new` loses `const`** (`crypto/mod.rs:267`): `Vec::new()` is const,
    `Context::new(&'static Algorithm)` is not, even though `suite.digest()` is
    (`:63-67`). No caller uses it in a const context today (all sites are
    `let ks = KeySchedule::new(…)`), so this is a documented public-API touch,
    not a break to work around.
  *Test:* (a) checkpoint semantics — hash after one append equals the hash of
  that message alone, and after a second append equals the hash of both (a
  Context accidentally finalized or shared would fail the first); (b) existing
  RFC 8448 vectors unchanged; (c) `KeySchedule` does not implement `Clone` and
  must not start (two schedules sharing one Context is the same defect class as
  cloned `AppKeys`).
  Note: `VerifyContext` is public, so the `SignedData` enum is a deliberate
  `0.1.0` API break; the only implementors in the tree are `WebPkiVerifier`
  (`verify/mod.rs:100`) and `AcceptAll` (`handshake/mod.rs:94`), so the blast
  radius is those two files plus three construction sites (`verify/mod.rs:646`,
  `:679`, `handshake/mod.rs:295`, `tls12.rs:324`). The transcript is public
  wire bytes, not key material — no zeroize requirement, and none of the auth
  path needs the raw bytes anymore.

**Acceptance S4:** `handshake` + `verify` suites green; the REALITY fallback
test still asserts `RealityFallback` against a plain-TLS peer.

### S5 — structure (mechanical, after S2)

- **T14** split `handshake/mod.rs` (1,190 source lines) into
  `handshake/{mod.rs (connect + re-exports), drive.rs (188-374), server_hello.rs
  (479-783 + `client_hello_extension`/`ensure_offered_sigalg`), flight.rs
  (815-1190)}`; tests move with their subject. No behaviour change, no
  re-export shims: `pub` items keep their paths, `pub(crate)` items are
  re-exported from `mod.rs` only where a sibling needs them.
  Do this **after** S2 so the retry logic is written once, in its final home.
  **Executed as a 2-module split** (`server_hello.rs`, `flight.rs`); `drive`
  stays in `mod.rs` with `connect` and the seams — see Execution notes.

### Deferred, not in this plan

- Spider-X relocation (D1) — needs the `ConnectOutcome` return type and a
  `leas-native` transport-phase owner; blocks nothing.
- Session resumption (D3) — measurement first.
- Curves for REALITY (claim 9) — doc-only, folded into T9.
- 0-RTT, ECH, server-side TLS, roster changes — unchanged non-goals.

## 5. Verification

| Slice | Command | Evidence it must produce |
|---|---|---|
| all | `cargo nextest run --workspace` | Summary line, not a per-crate green |
| all | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | the authoritative lint surface |
| S2 | `cargo nextest run -p leas-tls hrr` | new rows fail on `bb416a1`, pass after |
| S2 | `cargo run -p leas-tls --example probe_host -- <host> <port> <sni> 3` | live classification of a real host, recorded honestly |
| S2b | `cargo run -p leas-tls --example grader -- --roster` | 71/71 rows connect and report their pinned JA4 (offline-tier fidelity, no network) |
| S2b | the same round with `ech` stripped for the failing row | the before/after handshake table that decides T16's disposition |
| S3 | `cargo nextest run -p leas-tls key_update` | tunnel survives a peer KeyUpdate |
| docs | — | `native-core.md`, roster report, and this plan's execution notes |

Per-slice definition of done is unchanged from the review (compiles, existing
interop/REALITY tests pass, targeted tests added, non-goals stated, no `unsafe`,
no aws-lc-rs, no panic on recoverable config or wire error) — with one addition:
a panic that survives a `TryFrom` conversion is a defect even when "validated
upstream", because the crate is `0.1.0` and reachable from external callers.

## 6. Risks

- **Fingerprint drift on CH2** is the top compatibility risk: a rebuilt hello
  that silently changes extension order, cipher order or GREASE makes the retry
  worse than the failure. T6's byte-diff test is the mitigation, and it must
  compare *parsed* hellos, not our builder's intent.
- **HRR under REALITY** would produce a confusing mid-dial error if a REALITY
  path ever retries with a re-sealed session id. Keeping it fatal (D2) is a
  deliberate, documented limitation.
- **KeyUpdate state** must never expose two live keys for one direction: the
  rotation must consume the old `AeadKey` (move, not clone) and reset the
  sequence counter in the same step — a bug here is a nonce-reuse bug.
- **S5 churn** touches every handshake test's import path; do it in one commit
  with no logic edits so the diff is reviewable.

## Execution notes (2026-11-02)

**Gate state at start (T0) — scope, stated honestly.** On `bb416a1` the
per-crate baseline was green: `cargo nextest run -p leas-tls` (239 tests, 4
skipped) and `cargo clippy -p leas-tls --all-targets --all-features -- -D
warnings` clean. The **workspace** clippy gate was NOT run at base (the
plan's own trap warning applies in reverse: ADR 0011 records a pre-existing
workspace red, so base-vs-diff deltas across the whole workspace are not
available). It was run once, at the end, and came back clean — that is the
gate's current state, not a claim that the diff added nothing everywhere.

### What landed

| Task | Result |
|---|---|
| T1 | `SpecProvisioner` is `TryFrom<&Fingerprint> -> Result<_, TlsError>` holding a resolved `ClientHelloSpec`; `From` deleted; `new` takes a spec. `leas-native` maps a resolve failure to `NativeError::Config`. |
| T2 | ALPN typed as opaque bytes end to end (`BuildParams`, `HandshakeParams`, `HelloProvisionParams`, the spec encoders). The connect-time UTF-8 block is gone; the encoder still rejects a >255-byte entry. |
| T3 | `FixedChrome133` → `FixedChrome130Hybrid` across `leas-tls`, `leas-native`, and the live reference docs; the "Chrome-133-shaped" comments corrected. Historical `docs/aegis/**` records left untouched. |
| T4–T5 | HRR is detected on the magic random **before** the extension scan; `key_share` (2-byte `selected_group`) and `cookie` (0x002C) are parsed; the echo check and the TLS-1.3-only check moved with it. Retry policy: one attempt, plain TLS only, group must be in `supported_groups` and producible (0x001D / 0x11EC), else `TlsError::HelloRetryRequestUnsupported`. |
| T6 | `RecordingRng`/`ReplayRng` over the existing `SecureRandom` seam; `ExtensionSpec::Cookie`; CH2 rewrites only `key_share` and inserts the cookie after it, so the padding extension still lands the record on 512 bytes. Replay divergence is a hard error. |
| T7 | Post-retry transcript: `message_hash(ClientHello1)` (`HS_MESSAGE_HASH = 0xFE`), then **the HelloRetryRequest message itself**, then CH2 (§4.4.1). The HRR term was missing until the end-to-end rustls retry test caught it — the scripted tests could not. |
| T8 | 5 HRR tests + 2 helpers: hint-only / hint+cookie / cookie-only parsing, a non-HRR 2-byte `key_share` stays an error, a scripted end-to-end retry asserting random/session-id/GREASE/extension-set identity, an unsupported group as a typed error, and the 512-byte record on a classical retry. |
| T9 | `native-core.md` rows updated (client/record/handshake/crypto) and the "36 are HRR-limited" sentence replaced with the measured ECH discriminator; `amiabot-roster-report.md` annotated (see S2b). |
| T10–T11 | `AppSecrets` (zeroizing, moved not cloned) installed by the driver; `KeyUpdate` parsed and applied on read with a queued `update_not_requested` ACK; `poll_write` rekeys at the RFC 8446 §5.5 limit (`record_limit` / `should_update`) by sealing the `KeyUpdate` with the old key, then rotating. `"traffic upd"` added to the closed label map. |
| T12 | `TlsStream` policy doc block; `negotiated_alpn()` accessor (the server's selection is no longer discarded), asserted against the rustls interop server. |
| T13 | `KeySchedule.transcript` is a `ring::digest::Context`; `transcript_hash()` clones the context and finishes the clone; `transcript_bytes()` deleted; `VerifyContext.signed: SignedData::{Tls13Hash, Tls12Raw}`; REALITY verify takes the hash. `KeySchedule::new` lost `const` (documented). |
| T14 | `handshake/server_hello.rs` (types, record reader) and `handshake/flight.rs` (the encrypted flight) extracted; `drive`, `connect`, the seams, the wire helpers and all tests stay in `mod.rs`. |

### Deviations, with reasons

- **S2b is closed by evidence, not by the planned strip experiment.**
  `docs/reference/native-core.md` ("What tier 1's roster gate cannot see",
  written after the 2026-08-25 sweep) already records that the failing rows
  shipped a **0-byte `encrypted_client_hello` body** and that Cloudflare
  answered `alert 50` to it, and that
  `profiles::tests::every_roster_hello_has_rfc_minimal_extension_bodies` +
  `tests/strict_peer_presets.rs` closed the gate. The cross-tabulation in M6
  (36/36 fail with ECH, 0/35 pass with it) independently reproduces that
  correlation on the report's own rows. The report is annotated; the strip
  experiment is unnecessary, and the "roster goes green" claim still needs a
  live re-run before it is quoted.
- **M1/M2 folded into S2.** `drive` no longer takes `offered_compress`: both
  callers derive it from the hello actually sent (`compressed_algorithms`), so
  a REALITY hello built from a generated Chrome profile accepts an RFC 8879
  compressed Certificate instead of claiming it never offered one.
- **`HelloRetryRequestUnsupported` added** rather than reusing
  `HelloRetryRequest`: an unimplemented group is a different diagnosis from
  "retry not supported", and `leas-native`'s `map_tls_err` already has a
  catch-all arm for it.
- **S5 split is 2 files, not 4.** `drive` did not move into its own module:
  after extracting the two parsers, `mod.rs` holds the driver, both seams,
  `connect`, the wire helpers and the tests, which is a coherent unit. Moving
  `drive` would have meant a further re-export layer for tests for little
  gain.
- **`connect`/`connect_reality` now box their inner future.** The driver's
  future grew past `clippy::large_futures`'s 16 KiB threshold and flipped
  every `.await` site in tests/examples; one allocation per connection is the
  cheap fix and keeps the public `async fn` shape.

### Verification actually run

| Command | Result |
|---|---|
| `cargo nextest run -p leas-tls` | 251 passed, 4 skipped (was 239) |
| `cargo nextest run -p leas-native` | 708 passed, 2 skipped |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo nextest run --workspace` | 2588 passed, 11 skipped, 0 failed (95 s) |

Live tier-2 evidence obtained after the gate: `amiabot_sweep` was run on
2026-11-02 against amiabot.app — **71/71 profiles handshake** (0 `handshake`
flags, all `likely_human`), versus 35/71 in the 2026-08-25 baseline; 36 rows
fixed, 0 regressed, and every fixed row is from the ECH row set. Recorded in
`docs/research/amiabot-roster-report.md` as a second per-profile table.
Still not run: the `--roster` grader sweep (`cargo run -p leas-tls --example
grader -- --roster`), which needs the same network and is not a gate.
