# Design: leas-tls Fidelity — Verified Review Claims → Improvement Specs

### Grill outcomes (2026-11-05)

- **Era axis: generator table in `gen_specs.py`, keyed by browser major-version interval.** No runtime clamp, no deferral. PQ attested only where the era table permits; unattested-PQ rows go `low_fidelity`, which the resolver never defaults. Fingerprint-schema changes rejected.
- **JA4 default: FoxIO.** `ja4.rs` switches to FoxIO semantics (keep 0015 in hash2, GREASE-filter sig-algs); `peet_ws` variant retained opt-in for grader/live-diff. Docs stop claiming FoxIO while shipping peet. FoxIO primary source (FoxIO-LLC/ja4 `technical_details/JA4.md`, example hash `e5627efa2ab1`) is now on the record as the authority for the spec variant. The `common.py`/`TrackMe` citation strings from FidelityCross are dropped — they are not in this checkout and are not needed once JA4.md is cited.
- **Hash-churn sequencing:** all-at-once in S3 — three encoders + fixtures move together, gated by the one-line proof test first. Dual-ship rejected (two live encoders is the current bug).
- **HTTP/2 ownership: `Http2Profile` enum in leas-tls next to `ClientHelloSpec`,** keyed by `(Browser, Os, Device)` exactly like the roster rows. leas-native consumes, doesn't own the table. leas-native's `headers.rs` values become the seed data.
- **REALITY graft investigation (pre-author):** before S6, verify that the `chrome_130_hybrid_spec` graft (`reality/mod.rs:107-118`, inserting 0x11EC at position 1 in groups + keyshare) matches what a real Chrome 130 sends — including position, the sig-algs/ecpf context, and whether Chrome 130's `supported_groups` shows the hybrid at index-1. The eligible-pool size (20 vs 19) is decided by this finding, not by preference.
- **Slice order approved: S1 generator era/template/body cleanup (+ 0x0032 gate), S2 GREASE slots, S3 encoders, S4 small builder, S5 h2 coupling, S6 REALITY picker, S7 family-scoped permutation** — one slice at a time with the full gate each time.

- **Date:** 2026-11-05
- **Status:** **verified-evidence, awaiting approval** — this spec is the product of an Aegis verification pass over three external reviews (Kimi roster review, DeepSeek hello review, Grok REALITY-selection instruction). No code was touched in producing it. Every claim below carries a file:line verdict from the pass; refuted claims are recorded as errata so they are not re-implemented.
- **Kind:** spec
- **Owners:** `crates/leas-tls/src/profiles/**` + `crates/leas-tls/src/fingerprints/catalog/gen_specs.py` (roster), `crates/leas-tls/src/crypto/fingerprint/{ja3,ja4}.rs`, `crates/leas-tls/src/spec/{mod,grease}.rs`, `crates/leas-tls/src/hello/mod.rs`, `crates/leas-tls/src/http2/mod.rs`, `crates/leas-tls/src/reality/mod.rs` + `crates/leas-native/src/security/*`
- **External evidence read:** Kimi review (full text), DeepSeek instruction (attachment), Grok instruction (attachment); verification scouts read `profiles/**`, `hello/{mod,parse}.rs`, `spec/mod.rs`, `crypto/fingerprint/*`, `reality/mod.rs`, `fingerprints/{resolve,query}.rs`, `http2/mod.rs`, `fingerprints/catalog/gen_specs.py`, `leas-native/src/security/mod.rs`, `leas-native/src/headers.rs`.
- **Authority hardening (second pass):** `thirdparty/CycleTLS/cycletls/ja4.go` **does** exist and implements a JA4 variant inline, but it is **not** FoxIO primary source and shows no GREASE filtering in its TLS-hash path. The FoxIO `common.py` / "TrackMe" references cited by FidelityCross are **not in this checkout** (`grep -i ja4 thirdparty/` finds only CycleTLS/impit/ja4db-export contributors, none FoxIO). Consequently, all FoxIO-vs-peet direction claims below are recorded as **unverified-by-primary-source locally**: the local encoder (`ja4.rs:72-93`), the grader (`examples/grader.rs:442-445`), and the python mirror (`gen_specs.py:151`) are the only authorities available here, and they **disagree with each other** on the exact field in question.
- **Authority note:** `thirdparty/Xray-core|sing-box|v2rayN` **do** exist in this checkout (the advisory claiming otherwise was checked against `ls thirdparty/` and is wrong), but `thirdparty/shoes/src/reality/` **does** contain `reality_client.rs` where docs cite `reality_client_verify.rs` — that one "ported from" path is stale. Findings below ground on leas-tls source lines, not on external behavior claims.
- **External evidence read:** Kimi review (full text), DeepSeek instruction (attachment), Grok instruction (attachment); verification scouts read `profiles/**`, `hello/{mod,parse}.rs`, `spec/mod.rs`, `crypto/fingerprint/*`, `reality/mod.rs`, `fingerprints/{resolve,query}.rs`, `http2/mod.rs`, `fingerprints/catalog/gen_specs.py`, `leas-native/src/security/mod.rs`, `leas-native/src/headers.rs`.

## 1. Witness verdicts

### Kimi — roster review (claim-by-claim)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| K1 | Every generated profile carries `mlkem768` groups + keyshare regardless of era | **PARTIAL** — true only for `profiles/generated/chrome.rs` (19/69 rows, template constant) | `chrome.rs:192,204,216,228,407-408,423-424,438-439`; root cause `gen_specs.py:396-401,445-458` (family-keyed template, no era axis). `firefox.rs`/`safari.rs`/`chrome_android.rs`/`safari_ios.rs` have **zero** occurrences; 50/69 rows are `keyshare[x25519]` only. |
| K2 | `raw[0x0031,""]`/`raw[0x0016,""]` in chrome_93/edge_121/firefox_125/safari_5 are malformed bodies, missed by the MIN_BODY gate | **Presence CONFIRMED; "malformed" REFUTED; gate gap benign** | Both ids are legally zero-length (`0x0016` encrypt_then_mac, `0x0031` post_handshake_auth): `gen_specs.py:344-349` `EMPTY_BODY_OK`, `profiles/mod.rs:264-268`. The real (latent) gate hole is **`0x0032`** (must be non-empty, absent from Rust MIN_BODY) |
| K3 | Generated roster ships zero GREASE slots; only hand rows have them; this is the biggest cheap fidelity win | **CONFIRMED** | `grep -i grease profiles/generated/` = 0; `hand_selected.rs:20,24,49`; gate `profiles/mod.rs:409-414`; emitter rationale `gen_specs.py:288-291` |
| K4 | JA4 `t13d131000_f57a46bbacb6_e7c285222651` is one wire template shared by chrome_115+opera_98+firefox_150_macos, producing Firefox-headers/Chrome-TLS mismatch | **Collision CONFIRMED; "identical wire template" REFUTED** | Shared by **7** entries across 4 families (also edge_112, opera_97, opera_80_android, safari_17_ios_tablet); extension **order** differs between chrome_115 and firefox_150 (manifest query) — JA4 hashes are order-insensitive. Collision itself already documented: `docs/reference/tls-fingerprint-roster.md:25-29` ("69 → 18 distinct JA4s"). |
| K5 | Suspicious rows: safari_5_windows, safari_12_windows, brave 0x1304, `GENERATED.len()==69` fragility | **3 of 4 CONFIRMED; the 0x1304 part is REFUTED** | `safari.rs:135-144` (Safari 5/2010 emitting TLS 1.3; JA4 distribution chrome 133 / firefox 75 / opera 15 / safari 17); `safari.rs:109-118` (safari_12_windows with `ech` + delegated_credentials; JA4 93 firefox / 1 safari); `chrome.rs:420,435` (`0x1304` ∈ BoringSSL hello); `profiles/mod.rs:384` hardcoded 69 (+ `tests/generated_ja4_gate.rs:238-260`) |
| K6 | Giant blobs in git: catalog_data.rs 3.7M, specs_manifest.json 4.6M, ~80M fixtures | **CONFIRMED with correction** | `specs_manifest.json` 4,749,580 B; `catalog_data.rs` 3,857,709 B; `tests/fixtures/m1n1-5ub-*.txt` **36 files, 85.5 MB** — but they are vmess/vless **subscription feeds** for `leas-proto` tests, not TLS fixtures; already tracked in `docs/aegis/specs/2026-10-13-toolchain-portability-and-repo-weight-design.md:90` |
| K7 | `ja3.rs` ok, `ja4.rs` correct (peet vector, GREASE, 99-clamp, 0010/0015 exclusion) | **REFUTED** (see FidelityCross § below) | `ja4.rs:84-90` — hash2 sig-alg segment unfiltered; `ja4.rs:24` — 0x0015 exclusion is **peet-only, not FoxIO**; `fx. ja3 hex/comma = non-classic` |
| K8 | `grease.rs` `is_grease`/generation correct; test `GENERATED.len()==69` acceptable | **CONFIRMED, with defects** | `is_grease` exact 16 RFC 8701 values, uniform draw; but `random_grease` is dead code, and `sigalgs[grease]` is never randomized |

### DeepSeek — hello builder review (claim-by-claim)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| D1 | Extension order is fixed; browsers shuffle, so add permutation + `shuffle_extensions` flag + PSK-last | **Code facts CONFIRMED; premise PARTIALLY CONFIRMED (needs correction)** | `hello/mod.rs:277` fixed order; no shuffle anywhere; `ClientHelloSpec` is 5 fields (`spec/mod.rs:175-184`); no `pre_shared_key` `ExtensionSpec` variant by design (`gen_specs.py:830-845`, `tests/tls_peet_ws.rs:289-309` asserts absence). **What I originally claimed is wrong: Chromium/BoringSSL has shuffled since Chrome 108–110 (Jan 2023).** Primary sources: Chrome Platform Status feature 5124606246518784 (enabled by default, Chrome 110), David Adrian's blink-dev "extension permutation" thread and EXPLAINER (`github.com/dadrian/clienthello-randomization`), Fastly's Jan 2023 field measurement, crawlex version-by-version catalog. Constraint confirmed: `pre_shared_key` stays last. Firefox/NSS is different: Bugzilla 1789436 landed "CH extension permutation" FIXED ~3 years ago, but the NSS implementation was **not enabled by default**; follow-up Bugzilla 1816878 "Add Prefs for Client Hello Permutation and GREASE" is still OPEN, and a 2-year-old comment there says "Chrome has TLS extension permutation enabled by default. Privacy-focused browser hasn't." So BoringSSL/Chromium = shuffled on the wire; NSS/Firefox = library-capable, browser-default off, wire-verified per build (crawlex flags Firefox sources as disagreeing). `docs/reference/native-core.md:152-155` and `tests/fingerprints.rs:10-12` remain evidence for **order being meaningful fingerprint data** — they do **not** validate a claim that all current browsers emit fixed order. |
| D2 | `draw_grease_distinct` silently returns duplicate after 8 failed attempts | **CONFIRMED** | `hello/mod.rs:491-509` (`ATTEMPTS: 8`, `Ok(last)` at `:508`). Production P(collision⁸) = 16⁻⁸, but the degenerate fixed-seed RNG path returns a wire-duplicate extension type. |
| D3 | GREASE ECH payload length hardcoded (`ECH_PAYLOAD_LEN = 144`), not configurable | **CONFIRMED (PARTIAL framing)** | `spec/mod.rs:76` const; `EchGrease::default` `:84-91`; builder resets payload at `hello/mod.rs:180`; length not spec-reachable. Real browsers vary, but configurability is a **spec-but-no-knob** gap, not a fidelity emergency. |
| D4 | Parser may allocate huge buffers / panic on oversized length fields | **REFUTED as a live defect (parser already hardened); test-coverage gap CONFIRMED** | `parse.rs:41-145`: `Reader::take` uses `checked_add` + bounds-checked `get` (`:120-131`); every alloc copies an already-bounded slice (`:48-90`); no `Vec::with_capacity` in non-test parser code; SNI/ALPN bodies stay opaque (no inner decode). Truncation tests exist (`parse.rs:240-265`); oversized-length-specific negative tests do not. |
| D5 | `FixedRandom` 256×0x5A collapses all GREASE slots to 0xAAAA | **CONFIRMED** | `profiles/mod.rs:388-391,449-452`; 0x5A → 0xAAAA via `hello/mod.rs:470-478`; dedup gate filters GREASE out before checking (`profiles/mod.rs:483-492`), so the duplicate is invisible. Real impact: only under fixed-seed tests. |

### Grok — REALITY random eligible selection (design-fit verdicts)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| G1 | Default `FixedChrome130Hybrid` serves chrome_130 + grafted X25519MLKEM768 | **PARTIAL** — graft confirmed; "default" is conditional | Graft `reality/mod.rs:107-118` (groups insert 0x11EC at `:111-113`, keyshare at `:114-116`), static `:125-126`, struct `:134`. It is used only when no fingerprint id is configured (`leas-native/src/security/mod.rs:92-116`); with `fp` set, `SpecProvisioner` is built instead. |
| G2 | `SpecProvisioner` + `TryFrom<&Fingerprint>` general path exists | **CONFIRMED** | `reality/mod.rs:142-162`, construction `security/mod.rs:100` |
| G3 | Session-id is the auth slot; wire len 32 = 16-byte plaintext + 16-byte GCM tag; `SessionIdSpec::AuthPayload{len}` | **CONFIRMED** | `spec/mod.rs:96-104`; layout `messages.rs:23-40`, seal-len check `messages.rs:74-78`; `auth.rs:47-70` |
| G4 | The four `reality_eligible` predicates (TLS1.3 AEAD incl. GREASE exclusion, sid∈{32}, X25519 keyshare, ML-KEM hybrid) are usable per-spec | **Confirmed feasible; NOT implemented** | None of `supports_tls13_aead`, `session_id_wire_len`, `offers_x25519_key_share`, `offers_mlkem`, `reality_eligible` exist (repo-wide grep); only `offers_hybrid_key_share` (`reality/mod.rs:63-65,188-199`). All four predicates are new code. Eligible pool under Grok rules = **20/71** rows (19 chrome.rs rows + chrome_130 via graft). |
| G5 | Blockers for "uniform random pick + session-id-only transform" | **CONFIRMED** (5 items) | ① roster table is `pub(crate)` (`resolve.rs:63-80`) — no public enumeration; ② provisioner choice is static config (`reality.rs:23-28`, `security/mod.rs:92-117`), RNG must be handed off through `chain.rs:82` / `client.rs:36-57`; ③ ALPN hardcoded `reality/mod.rs:309` (Grok's "connector may override" is aspirational — builder can, caller path cannot); ④ transform forces sid 32 (legal, shifts padding; incompatible with Safari `session: empty`); ⑤ `Mlkem768::generate_keypair()` takes no `SecureRandom` (`crypto/mlkem.rs:230-233`) — test-seam gap |
### FidelityCross — encoder/cross-layer verdicts (found during verification, beyond the three reviews)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| F1 | JA4 matches FoxIO spec | **UNVERIFIABLE LOCALLY (direction contested between two in-repo encoders)** | `ja4.rs:24` excludes padding 0x0015 from hash2; documented in-repo as the peet variant (`gen_specs.py:142-146`: "Default excludes {SNI,ALPN} (ja4db/original-FoxIO rule); `exclude_padding=True` reproduces ja4.rs"). The spec example hashes asserted by repo constants only (`e5627efa2ab1` vs crate-pinned `f37e75b10bcc`, `tests/fingerprints.rs:23-24`); FoxIO primary source is absent from this checkout — `thirdparty/CycleTLS/cycletls/ja4.go` exists but is a Discord-maintained variant (its hash functions show no GREASE filtering and no FoxIO provenance). |
| F2 | JA4 GREASE handling everywhere | **PARTIAL (bug), fix requires authority decision not a one-liner** | counts/hash1/extension list strip GREASE (`ja4.rs:34-78`); hash2 sig-alg segment does not (`ja4.rs:84-90`), and the supporting test proves nothing about it — `grease_removed_from_counts_and_hashes` (`ja4.rs:159-164`) inserts GREASE into `ciphers`+`extensions` only, never `signature_algorithms`. In-repo encoders disagree: grader filters sigalgs (`grader.rs:442-445`), python mirror documents as a comment that it reproduces the omission (`gen_specs.py:151` "WITHOUT GREASE filtering"). Adding the filter changes pinned hashes and breaks tests (19/69 rows pass under the JA4 string in `generated_ja4_gate.rs:17-24`). A local one-line test addition (insert GREASE sigalg, assert hash2 invariance) would prove the divergence but **has not been run** — sequencing decision, not severity. |
| F3 | `ja4_a` hardcoded `t13d` | **CONFIRMED, latent** | `ja4.rs:53`; `Ja3Fields` has no version/SNI fields (`ja3.rs:15-30`), so `d` is fixed too. Roster gate `starts_with("t13d")` is tautological (`profiles/mod.rs:417`). No current row is TLS1.2-only, so no live mislabel. |
| F4 | `ja3.rs` is classic JA3 | **REFUTED** | Hex ids, comma-joined (`ja3.rs:130-155`) vs classic decimal/dash; repo admits it (`examples/grader.rs:15-20`). `ja3_grease_stripped` leaves GREASE curves (`ja3.rs:120`). |
| F5 | h2 SETTINGS + headers are "chosen by family" and can mismatch TLS spec | **PARTIAL** — mechanism inverted | Product runtime h2 is **family-blind**: empty SETTINGS, fixed headers (`http2/mod.rs:109-205`), hyper defaults for the real client (`transport/http/conn.rs:36-56`); per-family tables exist but are used **only by the sweep example** (`leas-native/src/headers.rs:176-190`, `examples/amiabot_sweep.rs:231,265-270`). Spider fallback pairs any fingerprint's TLS with fixed Chrome UA (`reality/spider.rs:24-37`). |
| F6 | `sigalgs[grease]` is randomized per connection | **LATENT (downgraded)** | DSL accepts `grease` inside `sigalgs[..]` (`profiles/mod.rs:71,199,259`) and the engine encodes `SignatureAlgorithms` verbatim (`spec/mod.rs:330-338`) — but **no shipped profile exercises it** (`hand_selected.rs:30-31,44-45` list concrete sigalgs only); the sole GREASE-sigalg occurrence is a test fixture (`profiles/mod.rs:522-523`). An untested escape hatch, not a live wire defect. `random_grease` dead (`spec/grease.rs`). |

## 2. Verified defects, ranked

| Rank | Defect | Impact class |
|---|---|---|
| 1 | **Era-anachronism** — chrome-desktop template stamps `mlkem768`+`x25519mlkem768` onto Chrome 89–115 / Opera 97-98-era rows where PQ did not exist (K1 partial, verified at `chrome.rs:192-439` + `gen_specs.py:396-401`) | Wire-detectable: key_share bytes in clear contradict "Chrome 93" |
| 2 | **No GREASE on generated roster** (K3) | Structural: every real Chromium hello carries ≥4 GREASE slots; JA3/JA4 hide it, wire doesn't |
| 3 | **JA4 encoders not FoxIO-conform** — hash2 sigalgs unfiltered (F2); 0015 peet/FoxIO divergence mislabeled as FoxIO (F1); A-part hardcoded `t13d`/`d` (F3) | Fingerprint-comparison errors everywhere (incl. grader) |
| 4 | **`draw_grease_distinct` silent duplicate fallback** (D2) + grease-blind roster dedup gate (D5) | Wire-invalid under degenerate RNG; masks D2 in tests |
| 5 | **Data-quality rows** — impossible browser/OS pairs and synthesized bodies beyond JA4 (K5 minus the 0x1304 clause, which is IANA-assigned; the engine simply cannot negotiate it: `crypto/mod.rs:1087`) | Dedup/integrity: roster advertises hellos no browser sends |
### D7 hardening (second pass)

**1. JA4 (D7) — BLOCKED ON AUTHORITY DECISION, not on code.** Two in-repo JA4 implementations disagree on (a) whether hash2 filters GREASE sigalgs and (b) whether padding 0x0015 is inside hash2. The crate's comments say one thing ("final FoxIO scheme", `ja4.rs:1`), the grader does another, and the python mirror encodes the discrepancy as a comment. FoxIO primary source is not in this checkout. Sequencing for S3 must therefore be: **(i)** run the one-line GREASE-sigalg test to pin today's divergence in writing, **(ii)** decide the authoritative variant (peet-vs-FoxIO, GREASE-filter on/off) on a source we can actually cite, **(iii)** then update all three encoders in one slice. Specifying "add the filter" now picks a side without evidence.

**2. `sigalgs[grease]` — LATENT, not live (downgraded from F6).** Confirmed by fresh read: `spec/mod.rs:330-338` encodes `SignatureAlgorithms(schemes)` verbatim, and the DSL accepts `grease` inside `sigalgs[..]` (`profiles/mod.rs:71,199,259`). But **no shipped profile exercises it**: `hand_selected.rs:30-31,44-45` list concrete sigalgs only. The sole GREASE-sigalg occurrence is a test fixture (`profiles/mod.rs:522-523`). So the static-GREASE-on-the-wire claim is latent (an untested escape hatch), not a live fidelity defect. Ranked at 8 in §2.

## 3. Errata — do NOT implement

| Claim | Why it is wrong |
|---|---|
| DeepSeek extension permutation (§D1) — **PARTIALLY CORRECTED ON WEB EVIDENCE (see D1 table)** | BoringSSL/Chromium shuffles since Jan 2023 (Chrome 108/110); NSS has the library option (Bugzilla 1789436 FIXED) but the follow-up pref bug (1816878) is still open and Firefox does not enable it by default. The correct fix is **family- and era-scoped** (shuffle for Chromium ≥108, fixed for pre-108 and for Firefox-default profiles), not a blanket flag. A naive always-shuffle would destroy the fingerprint identity for pre-108 and NSS-backed profiles and break CH2 replay equality on those paths. |
| Kimi "0x0016/0x0031 empty bodies are malformed" (K2) | Both are RFC-legal zero-length bodies (`0x0016`, `0x0031` ∈ `EMPTY_BODY_OK`). Real browsers don't send them, but the encoding is not malformed. Template rows carry them anyway because the ja4db corpus includes them — removal is D3 below on fidelity grounds, not well-formedness. |
| Kimi "identical wire template" across families for `t13d131000…` (K4) | Extension order differs by family; bytes differ. JA4 (order-insensitive) collides; the wire does not. The cross-layer risk (K4's `headers↔TLS` mismatch) is real but its mechanism is F5 (runtime h2 is family-blind), not an identical-template collision. |
| DeepSeek "parser hardening needed" (D4) | Parser already uses checked, bounds-verified takes on every length field; no alloc-amplification or panic path exists. Only negative-test coverage is missing. |
| K6 blob sizes as TLS findings | Catalog blobs confirmed; the 85 MB fixtures are subscription feeds unrelated to TLS, and the repo-weight reduction is already tracked in the 2026-10-13 spec. Out of scope here. |

## 4. Decisions

### D1 — Era-correct the roster at generation time

- Root cause is `gen_specs.py:396-401` (chrome_desktop template hard-codes `[0x11EC, 0x001D, 0x0017, 0x0018]` / `["X25519Mlkem768","X25519"]`) with `template_for()` (`:445-458`) keyed on family only.
- Add an **era axis**: template parameters keyed by browser major-version interval; X25519-only before the PQ rollout, explicit 0x6399-era entries only where attested. Rows with unattested PQ are `low_fidelity` and **must not** claim a real browser identity in `resolve.rs`.
- Emission invariants, enforced in `gen_specs.py` selftest + build:
  1. `key_share groups ⊆ supported_groups`;
  2. (withdrawn) the cipher-codepoint check: 0x1304 is IANA-assigned, so it is not an invariant;
  3. browser/OS/device triple is source-attested (safari on Windows post-5.1.7, Chrome 93 with ECH, etc. drop or demote to `low_fidelity`).
- Regenerate `profiles/generated/*.rs` via existing pipeline (gen → manifest → `catalog_data.rs` + `specs_manifest.json` refresh), and update `profiles/mod.rs:384` + `tests/generated_ja4_gate.rs:238-260` hard-coded counts as **data**, not literals.
- No hand-edit of generated rows; no schema bump (`SCHEMA_VERSION` untouched — roster rows are catalog data, not schema).
- **Executed outcome (S1):** `PQ_ERA` gates the hybrid. Chromium <124 → X25519-only groups/key_share; ≥131 → `X25519MLKEM768`; 124–130 → `X25519Kyber768Draft00` only where the family template already advertises it (today none, so those rows emit X25519-only rather than inventing a codepoint). Firefox rows stay X25519-only: the firefox template carries no PQ group, and the era gate only filters what the template lists, so there is no Firefox transition to make here (a real Firefox ≥132 hybrid would require the template to advertise `0x11EC` first). Safari stays X25519-only. Result: 4 of the 19 chrome-desktop rows keep a hybrid share (`chrome_143`, `chrome_149`, `edge_132`, `edge_148`), the rest do not; `chrome_93_windows_desktop` and `chrome_115_macos_desktop` are now X25519-only.
- Cipher-codepoint validation: **no row was dropped.** `0x1304` is `TLS_AES_128_CCM_SHA256` (RFC 8446 B.4; `thirdparty/utls/dicttls/cipher_suites.go:160`), i.e. assigned — the "0x1304 is unassigned" premise was wrong. What the crate cannot do is *negotiate* it: `crypto/mod.rs:1087` asserts `CipherSuiteId::from_u16(0x1304) == None`. That is an engine-support gap, out of S1 scope; the roster keeps `brave_89`/`brave_90` intact. Roster stays **69**; the only class shift is era-driven (padding-omitted 4 → 0, padding-in-hello 16 → 20).

### D2 — GREASE-ify the generated roster

- **Executed (S2):** `chrome_desktop` and `chrome_android` templates carry `grease=True`; `synthesize_wire` prefixes the GREASE cipher, emits the standalone GREASE extension, and injects GREASE into `supported_groups`, `key_share` and `supported_versions`. Firefox/Safari/Safari-iOS/okhttp/fallback stay GREASE-free. JA4 class counts are unchanged (`49/20/0/0/3`), which is the proof that GREASE is fingerprint-invisible; the new `all_profiles_build_and_parse` invariant asserts the family split in both directions (Chromium rows carry a GREASE cipher + ≥1 GREASE extension; non-Chromium rows carry none), scoped by template family rather than brand so iOS rows stay Safari-shaped.

- Emit the four Chromium GREASE slots (cipher first, first extension, first group, first `supported_versions`, first key_share entry) for chromium-family rows, mirroring `hand_selected.rs:20,24` positions; browser-family-specific placement rules live in `gen_specs.py` (already present as the `grease` placeholder path at `:572-573`).
- GREASE does not move JA3/JA4, so catalog JA4 stats must stay byte-identical post-change — asserted by `tests/generated_ja4_gate.rs`.
- Hand-row GREASE slots are the reference positions. **Golden wire check: NOT done — deferred.** No Chromium ClientHello capture exists in this checkout (searched `thirdparty/`), and manufacturing one from memory would be a fake oracle. What is verified instead: JA4 class counts are byte-identical before/after GREASE injection (`49/20/0/0/3`), and a family-scoped invariant asserts Chromium rows carry GREASE while Firefox/Safari/iOS rows do not. Capture-based comparison stays an open item for a network-capable run.

### D3 — `post_handshake_auth`/`encrypt_then_mac`: keep when the corpus carries them

- Not a malformed-body fix (erratum K2) — both are RFC-legal zero-length bodies.
- **Executed outcome (S1):** the ids stay when the corpus row carries them. Removing them changes the extension count and hash2, i.e. it is a roster-identity change, not a body fix; corpus fidelity wins and the ids remain. The `EMPTY_BODY_OK`/`EMPTY_BODY_ILLEGAL` codec paths are untouched.
- A stronger browser-fidelity variant (drop them always, accept JA4 churn) stays available as a later roster-wide decision, tracked here so it is not re-litigated by accident.

### D4 — Close the `0x0032` gate hole; attribute data-quality failures

- Add `(0x0032, 2, "signature_algorithms_cert")` to `MIN_BODY` (`profiles/mod.rs:433-444`). Current emission is non-empty, so this is a regression gate, not a shape change.
- At emission, reject `raw[ty, ""]` when `ty ∉ EMPTY_BODY_OK` (mirrors `gen_specs.py:344-349` exactly), including unknown `0x3374`-style ids emitted as empty.
- Murkier data rows (K5): `safari_5_windows`, `safari_12_windows` etc. either demote to `low_fidelity` or drop from the default-resolved catalog; duplicate-UA browser/OS pairs with >10:1 distribution skew are demoted. Resolution defaults never route a dial to an unattested identity.

### D5 — Make `draw_grease_distinct` a hard error

- **Executed (S4):** returns `TlsError::Crypto` after 8 collisions instead of the last duplicate (no `Internal` variant exists; `Crypto` is the RNG-failure class). New test: two GREASE extension slots + a constant RNG → typed error, nothing emitted. The roster tests moved from the flat `0x5A` fixture to a nibble-cycling one because `edge_106`'s two slots legitimately need distinct draws.

- **Exposure after S2 (measured with a throwaway probe, since deleted):** every Chromium-family *generated* spec has exactly **one** standalone GREASE extension slot, one GREASE cipher slot, one GREASE group and one GREASE key share, so the constant-RNG fixture yields no duplicate on any of the 69 generated rows — verified by building all of them under the `0x5A` fixture and comparing GREASE id counts. The duplicate is real but confined to `edge_106` (two standalone `grease` tokens, `hand_selected.rs:24,49`), which emits `0xAAAA` twice. S2 therefore does **not** multiply a 35-row exposure; the defect stays real and stays in S4.
- **Dedup gate tightened now:** duplicate extension types are wire-invalid for *every* id, GREASE included. The gate no longer filters GREASE before the sort/dedup for generated rows — it asserts zero duplicates there, and exempts only the two hand rows with the reason named (`edge_106`'s second slot needs the D5 hard error, S4). The previous "that is the fixture, not the spec" comment, which masked the collision, is gone.

- Switch the post-8 collision return from `Ok(last)` to `Err(TlsError::Internal(..))` — call sites already propagate with `?` (`hello/mod.rs:266,305,461`).
- Remove/guard the now-illegal "fixed-seed all-equal" expectation: any test that relied on the fallback switches to a distinct-value fixture. New test: constant RNG → build fails with the typed error (no duplicate emitted).
- No feature flag: a build path that can emit duplicate extension types on "success" is a correctness defect, not a mode.

### D6 — Add ECH payload-length config

- **Executed (S4):** `ExtensionSpec::EchGrease { payload_len: Option<usize> }`, DSL form `ech[N]`; `build_hello` sizes `RuntimeValues.ech.payload` from it and keeps `ECH_PAYLOAD_LEN` (144) as the default. Chosen over a `BuildParams` field because that would have touched 31 literals for a knob no profile varies; the enum change touches four match sites and the `spec!` macro.

- New optional field on the builder inputs: default 144 (current wire behavior, pinned by `spec/mod.rs:626-669` tests), override from `ClientHelloSpec` or `BuildParams` (one owner — `BuildParams`, since payload length is runtime material, not identity).
- `build_hello` stops resetting `RuntimeValues.ech` to `EchGrease::default()` unconditionally (`hello/mod.rs:180`); `EchGrease::default()` stays for the zero-config path.

### D7 — Encoder correctness: parameterize JA4 by variant; fix JA3

- **Executed (S3):** `Ja4Variant { Foxio (default), PeetWs }`. FoxIO keeps padding in `hash2` and GREASE-filters the sig-alg segment; PeetWs reproduces the old pin byte-for-byte. A-part now derives `t13`/`t12`/… from `supported_versions` (u8-length body, previously mis-parsed by the u16 reader) and `d`/`i` from SNI presence. ALPN follows the FoxIO table (first+last alnum char; hex fallback), empty lists render `000000000000`. Offline gate: **full-hash 49 → 66**, the 3 residual `ht` rows differ only in the corpus's `http/1.1` → `ht` letter. `sigalgs[grease]` is now drawn per connection instead of emitting `0xCACA` (new test proves the sentinel never reaches the wire) — note the draw uses `grease_a`, the **extension-body pairing** value shared with the first cipher/group/version/key-share slot (BoringSSL semantics), not a fresh per-namespace value; no shipped profile exercises it, so the pairing choice is latent; `ja3_grease_stripped` strips GREASE curves too; classic decimal/dash JA3 added beside the historical hex form.

- `ja4.rs`: **do not prescribe the filter direction until the authority decision in §4 D7 hardening is made.** The hash2 sig-alg segment (`ja4.rs:84-90`) diverges from the grader (`grader.rs:442-445`), and the supporting test (`ja4.rs:159-164`) covers only ciphers/extensions GREASE — never `signature_algorithms`. First step is the one-line proof test; the filter change then lands in one slice with all three encoders (`ja4.rs`, `grader.rs`, `gen_specs.py:151`) and their pinned hashes. Mirror in `gen_specs.py:149`.
- Parameterize the 0015 rule the same way: whichever variant a consumer needs is explicit, not baked into one encoder's `HASH2_EXCLUDED` (`ja4.rs:24`).
- Fix A-part: derive `t1X` from `supported_versions`, `d` from SNI presence — requires threading both into `Ja3Fields` or a small `Ja4Fields` struct (F3). Gate at `profiles/mod.rs:417` becomes non-tautological.
- ALPN rendering: single-char duplication and per-byte non-ASCII substitution per FoxIO (F2-cluster); empty-list hashes become `000000000000`.
- `ja3.rs`: add a classic encoder (decimal, dash/comma separators; GREASE-stripped curves fixed in `:120`); keep the current hex/comma canonical form as an explicitly-named variant (`ja3_hex`) so existing stored values don't quietly change meaning.
- `sigalgs` GREASE: route through the same fill-grease path as groups/versions (`hello/mod.rs:311-337`, `spec/mod.rs:330-338`); delete dead `random_grease` or wire it as the shared helper.
### D7 hardening (second pass)

**1. JA4 (D7) — BLOCKED ON AUTHORITY DECISION, not on code.** Two in-repo JA4 implementations disagree on (a) whether hash2 filters GREASE sigalgs and (b) whether padding 0x0015 is inside hash2. The crate's comments say one thing ("final FoxIO scheme", `ja4.rs:1`), the grader does another, and the python mirror encodes the discrepancy as a comment. FoxIO primary source is not in this checkout. Sequencing for S3 must therefore be: **(i)** run the one-line GREASE-sigalg test to pin today's divergence in writing, **(ii)** decide the authoritative variant (peet-vs-FoxIO, GREASE-filter on/off) on a source we can actually cite, **(iii)** then update all three encoders in one slice. Specifying "add the filter" now picks a side without evidence.


### D7 hardening, third pass (2026-11-05, local arbitration)

**1. Padding axis (0015) — DECIDABLE LOCALLY, decides for FoxIO/ja4db.** `gen_specs.py:17-23` documents `thirdparty/ja4db-export` as FoxIO's "original FoxIO tooling"; the join relies on it (`:159-169`). Run this session against the local CSVs:
   - 2,000/2,000 sampled string rows containing `0015` produce different hash2 under keep vs exclude — the axis is real.
   - Of 300 sampled `0015`-bearing rows, **264** have their recomputed **keep-0015 (default-ja4_hash)** value registered in `ja4_fingerprint.csv`; **0** of those 264 match the exclude-0015 variant. (`load_raw_rows` keys are by construction default-variant — this check is against the **registered** strings in the hash CSV, which is an independent check, not the module's own keying. 300 sampled rows: 264 distinct registered; 36 string-side-only rows absent from the hash export — corpus-set asymmetry, documented in the module docstring.)
   - Decision: **the crate default encoder keeps 0015 (FoxIO/ja4db); peet's exclusion is the opt-in.** Grilled answer "FoxIO default" is now backed by a citable local experiment, not a judgment call.

**2. Sigalgs-GREASE — unanswerable from any local source (recorded, not disputed).** Full 16-codepoint `0a0a..fafa` sweep over the first 200,000 `t13d` string rows in `ja4_fingerprint_string.csv`: **zero hits**. No row arbitrates the filter direction. Consequences:
   - `hash2`'s lack of a sig-alg GREASE filter is a **convention-level divergence** (`ja4.rs:84-90` vs `grader.rs:442-445`), not a corpus-provable defect. Re-worded as "correct-by-convention, untestable against local corpus."
   - Since no shipped profile emits GREASE sig-algs (`hand_selected.rs:30-31,44-45` concrete only; generated roster GREASE-free per K3; peet vector sigalgs all non-GREASE), the filter is a **no-op on every pinned hash in the current roster** — the earlier "adding the filter breaks the roster" phrasing is retracted for this roster. It remains a cross-encoder-consistency item for S3's three-encoder slice.
**2. `sigalgs[grease]` — LATENT, not live (downgraded from F6).** Confirmed by fresh read: `spec/mod.rs:330-338` encodes `SignatureAlgorithms(schemes)` verbatim, and the DSL accepts `grease` inside `sigalgs[..]` (`profiles/mod.rs:71,199,259`). But **no shipped profile exercises it**: `hand_selected.rs:30-31,44-45` list concrete sigalgs only. The sole GREASE-sigalg occurrence is a test fixture (`profiles/mod.rs:522-523`). So the static-GREASE-on-the-wire claim is latent (an untested escape hatch), not a live fidelity defect. Ranked at 8 in §2.

### D8 — Couple runtime h2/UA to the resolved fingerprint identity

- **Executed (S5):** `leas_tls::Http2Profile` (`for_browser` / `for_identity` / `settings`) is now the single table; `Resolved::http2_profile()` derives it from the resolved identity (iOS ⇒ Safari-shaped whatever the brand). The REALITY spider takes `SpiderConfig::browser`, set from the configured fingerprint in `leas-native`, and builds its navigation headers from the profile — closing the "Firefox TLS + Chrome UA" mismatch. `leas-native::headers::h2_settings` delegates to the profile, removing the duplicate table. **Deliberate non-change:** the proxy's own control channels (`transport/http/conn.rs` → v2rayhttp/xhttp) keep hyper defaults; they carry proxy protocol traffic, not browser navigation, so making them browser-shaped would be a *new* tell rather than a fix. Recorded so the gap is a decision, not an omission.

- Runtime HTTP/2 (grader client, spider, product hyper client) picks SETTINGS + user-agent/header family from the **resolved fingerprint's browser family**, never from the TLS spec's JA4 collision class (F5, G-blocker-adjacent).
- Owning table: promote `leas-native/src/headers.rs:36-92,176-190` (currently sweep-only) into a shared leas-tls enum keyed by `Browser`/`Os`/`Device` from the roster row, or expose a `Http2Profile` alongside `ClientHelloSpec` in `fingerprints/resolve.rs`.
- Fix spider: it must use the fingerprint's UA family, not fixed Chrome (`reality/spider.rs:24-37`).
- TLS extension order stays per resolved row (D1/D2 data) — the mismatch is resolved by construction, closing the K4 concern at its actual mechanism.

### D9 — REALITY: uniform random pick over eligible specs (Grok slice)

- **Graft investigation (grilled precondition), result: do NOT include the graft.** `chrome_130_hybrid_spec` inserts `0x11EC` into a Chrome-130 identity, but `X25519MLKEM768` shipped in Chrome 131 (Chrome 130 carried the draft `0x6399`), so the grafted wire is a combination no Chrome 130 emitted — the same era-anachronism class S1 removed from the generated roster. xray's REALITY server only *logs* whether the share is hybrid (`thirdparty/Xray-core/transport/internet/reality/reality.go:104`), so PQ is not a protocol requirement. Pool is therefore the **raw** roster: **46 eligible** (44 generated + 2 hand), no graft. A REALITY caller that wants PQ can pick a ≥131 row, which offers `0x11EC` natively.

Scope exactly as instructed — eligibility filter + uniform random pick + session-id-only transform. No poisoning, no weights, no sticky state, no synthetic fingerprints, no ML-KEM injection.

- **Executed (S6):** predicates live on `ClientHelloSpec` (`supports_tls13_aead`, `session_id_wire_len`, `offers_x25519_key_share`, `offers_mlkem_hybrid`, `reality_eligible`). `reality_candidates()` returns the eligible roster (`46` rows), `random_reality_spec(rng)` draws 8 RNG bytes and indexes uniformly, and `RandomEligible` is a `HelloProvisioner` that picks once per `provision` call and delegates the session-id-only transform to `SpecProvisioner`. `HelloProvisionerChoice::RandomEligible` exposes it through `leas-native`. Tests: every candidate is eligible and unique; 32 seeded picks all land on eligible rows.
- Regression protection: property test that every selected spec satisfies `reality_eligible` and that the session-id transform changes **only** the sid bytes (remainder byte-equal), preserving Grok constraint 4.
- Explicit non-goals carried from the instruction: classical-only remains eligible (no PQ requirement), no per-ASN weighting, no failure-history exclusion.

### D10 — Parser coverage only

### D11 — Permutation, scoped (added on web evidence)

- **Executed (S7):** `hello::build_hello_ordered(spec, params, permute)` (with `build_hello` delegating `false`), `handshake::connect_with_permutation` threading the flag through both the first hello and the HRR replay, and `client::permutes_extensions(requested, resolved)` deciding from the resolved identity: Chromium brands at major ≥108 permute, Firefox's default build and Safari never do. `permuted_order` is a Fisher–Yates over the spec indices with a 4-byte draw per swap, keeping padding last and `pre_shared_key` last-of-all (RFC 8446 §4.2.11). Chosen as a *handshake* flag rather than a spec field so the generated roster stays data-only and no struct literal churned. Tests pin: two connections differ, padding stays last, the non-GREASE set is unchanged, unpermuted builds keep spec order, and the family/era policy table.

- Chromium ≥108 (BoringSSL) permutes the extension order per connection, `pre_shared_key` remaining last (Chrome Platform Status feature 5124606246518784, David Adrian EXPLAINER, Fastly field measurement). Profiles ≥108 must shuffle; pre-108, Firefox-default NSS, and Safari profiles must **not** (NSS option exists since Bugzilla 1789436 FIXED, but the enabling pref bug 1816878 is still open and Firefox does not enable it by default).
- Implementation: `ClientHelloSpec` flag (e.g. `permute_extensions: bool`) default off; the permutation set excludes `0x0029` and runs after GREASE slot insertion, before length computation.
- Consequence, already established: raw JA3 is meaningless for ≥108 Chromium (per-connection value); all comparisons must be JA3N- or JA4-shaped.

## 5. Sequencing (by fidelity impact ÷ risk)

| Slice | Content | Size |
|---|---|---|
| S1 | D1 + D4 + D3 (roster era/template/body cleanup, generator invariants, regenerate) | One generator change + regenerated outputs; gate counts updated |
| S2 | D2 (GREASE-ify generated rows; capture-based golden check **deferred — no local capture**) | Generator emission only; JA4 stats provably unchanged |
| S3 | D7 + D8-encoder-half (JA4 variants, JA3 classic, sigalgs GREASE) | Encoder code + mirrors; encoder change invalidates pinned hash constants — all `grader.rs`/`gen_specs.py` mirrors and `tests/fingerprints.rs` pins update in one slice |
| S4 | D5 + D6 + D10 (draw_grease error, ECH length config, parser negative tests) | Small, independent |
| S5 | D8 (runtime h2/UA family coupling, spider fix) | Cross-crate (leas-tls + leas-native) |
| S6 | D9 (REALITY eligible-random) | New predicates + picker + gating; depends on S1–S2 for an era-clean pool |
| S7 | Permutation: family- and era-scoped extension-order shuffle for Chromium ≥108; fixed order otherwise, PSK-last | Builder path only; flag default **off** for pre-108/Firefox/Safari profiles, on for ≥108 Chromium. Anything doing order-sensitive comparison must use JA3N (sorted) or JA4. |

## 6. Non-goals

- No naive always-shuffle permutation — family- and era-scoped only (erratum D1, corrected on web evidence: Chromium ≥108 shuffles, Firefox-default NSS does not).
- No global/contextual fingerprint poisoning, weighted REALITY choice, per-ASN stats, sticky-per-profile, explore/exploit — Grok explicitly out-of-scopes all of these.
- No ALPN override for REALITY callers (G5-③) — builder supports it; caller plumbed only if a slice needs it.
- No repo-weight/blob work — tracked separately (2026-10-13 spec covers the 85 MB fixtures).
- No `SCHEMA_VERSION` bump anywhere in this spec (catalog data only).

## 7. Verification plan

- Full gate per slice: `cargo fmt`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace` (Summary line evidences completion; per-crate clippy is a trap per `AGENTS.md`).
- S1/S2: `tests/generated_ja4_gate.rs` passes; counts updated from data; `gen_specs.py` selftest green.
- S3: FoxIO example vector reproduces `e5627efa2ab1` under the spec variant and `f37e75b10bcc` under the peet variant — both pinned.
- S4: constant-RNG build errors typed; ECH length round-trips through parse; oversized parser inputs rejected without panic.
- S5: spider + runtime path use the resolved fingerprint's family (golden assertion on SETTINGS bytes per family).
- S6: every selected spec passes `reality_eligible`; sid-only byte-diff property test; distribution smoke test over seeded RNG (uniform over eligible count).
- Live network checks (peet.ws diffs, real browser pcaps) excluded by scope — agent cannot verify peet.ws vectors offline; the live test stays `#[ignore]`d as today.
- Examples are not test targets: `crates/leas-native/examples/amiabot_sweep.rs:63-72` iterates the 69 `GENERATED` rows and is covered by compile + JA4 gate only. "Era rows still connect" needs a new hermetic test or a tier-2 sweep, tracked as a known gap rather than assumed green.

---

### Reviewer checklist (grilled 2026-11-05 — answers above; this list is for execution-time verification only)

- [x] S1/S2 era table — generator table keyed by browser major; runtime clamp and deferral rejected.
- [x] D3 post_handshake_auth removal — keep in `EMPTY_BODY_OK` codec, drop from templates (implementation item, still in S1).
- [x] D7 variant default — FoxIO default, peet opt-in.
- [x] D8 table ownership — `Http2Profile` in leas-tls.
- [x] D9 graft handling — **investigate before coding**; pool size decision pending the graft-wire investigation.
