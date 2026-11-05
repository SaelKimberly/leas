# Plan: leas-tls S1 — roster era axis, 0x0032 gate, template body cleanup

- **Date:** 2026-11-05
- **Spec:** [`specs/2026-11-05-leas-tls-fidelity-design.md`](../specs/2026-11-05-leas-tls-fidelity-design.md) (grilled 2026-11-05) — slices D1 (era axis), D4 (`0x0032` + invariants), D3 (template raw drops)
- **Status:** draft — awaiting user approval to execute
- **TDD Route:** `auto` → **strict** for T2 (era table — behavioural, fingerprint-defining) and T3 (gate); **light** for T4/T5 (regeneration mechanics, counts). The verifier is the existing offline JA4 gate (`tests/generated_ja4_gate.rs`) + the generator's own `--selftest` — both already exist and are reused, not duplicated. (The golden-vectors question is settled by not inventing new fixtures.)

## Goal

Make the generated roster era-honest: stop stamping the 2024 `X25519MLKEM768` key share onto Chrome 89-115-era rows, close the latent `0x0032` mass gate hole, drop bodyless non-browser template extensions that real clients never send, and re-derive every count from the manifest instead of hard-coding them — without changing any JA4 the roster registers (JA4 is keyed to the corpus, and the corpus does not carry key-share bodies).

## Baseline / Authority Refs

- `gen_specs.py` today: `FAMILY_TEMPLATES` `:393-437` (chrome_desktop hard-codes `[0x11EC, 0x001D, 0x0017, 0x0018]` / `["X25519Mlkem768", "X25519"]` at `:395-398`); `template_for` `:446-462` (family-only, no era axis); `synthesize_wire` `:555-618` (wire table is why today only `chrome.rs` has ML-KEM).
- Emission discipline: `gen_specs.py:28-51` documents that `--manifest` MUST run before `--emit` or a body fix is silently reverted (happened 2026-09-17). Authority is the module itself; this plan honours it by putting the fix in `synthesize_wire`/templates, never by hand-editing `profiles/generated/*.rs`.
- Roster selection: `select_roster` `:834-869`, `FAMILY_RANGES` `:815-819`, `KEPT_STATS` `:873-907` (69 names), `is_psk` `:830-831`.
- Corpus: `thirdparty/ja4db-export/csv/` (11 MB `ja4_fingerprint.csv`, 24 MB `ja4_fingerprint_string.csv`) — regeneration input exists locally, no network required.
- Gates: `tests/generated_ja4_gate.rs` (offline JA4 oracle; docstring `:17-26` already classifies the peet-vs-corpus padding split that S3 will resolve), `profiles/mod.rs:384` (`len == 69`), `generated_ja4_gate.rs:238-261` (69/49/16/4/3 hardcoded), `gen_specs.py --selftest` `:872-873` (KEPT_STATS verbatim).
- Era anchors (web-verified this session): Chrome 124 pre-standard `X25519Kyber768Draft00` (0x6399) default; Chrome 131 standardized `X25519MLKEM768` (0x11EC) Nov 2024; Firefox 132 `X25519MLKEM768` default (`security.tls.enable_kyber` pref); crawlex version catalog. These are the only version facts the era table needs; they come from primary-ish secondary (catalog) corroborating Chrome Platform Status, not from memory.

## Compatibility Boundary

Roster rows are catalog data, not schema. `SCHEMA_VERSION` untouched; no DB migration. `ClientHelloSpec` unchanged. The manifest (`specs_manifest.json`, 4.5 MB) and the catalog (3.7 MB) regenerate from the same CSV inputs deterministically; both are committed outputs. External consumers of `GENERATED` (`fingerprints/resolve.rs`, `tests/generated_ja4_gate.rs`, the audit tools) see a changed wire body for ≤19 chromium rows and possibly a smaller roster if `low_fidelity` rows are demoted out of the default resolution — that is a deliberate, spec-approved change, not an accident.

## Change Necessity

No docs-only or config-only route exists: the defect is generated data (era-blind templates) plus two hand-maintained Rust gates. The fix must live in the generator (`gen_specs.py`) so regeneration preserves it, and the gates must accept the corrected counts as data, not literals.

## Ripple Signal Triage

Shared contract: `specs_manifest.json` ↔ `profiles/generated/*.rs` ↔ `GENERATED` gate. Single owner after S1: `gen_specs.py` (`synthesize_wire` + era table). Adding the era axis changes the wire body of every `< 131` chromium row (groups + keyshare); downstream tests that pin full JA4 equality per-row (`generated_ja4_gate.rs`) and the strict-peer preset tests (`tests/strict_peer_presets.rs`) are the consumers that must stay green. Expanded verification is therefore: `--selftest` green + `--emit` deterministic + the JA4 gate reproduces every entry's registered/ja4db-source JA4 via the *already-documented* semantics classes (49 full / 16 padding-in-hello / 4 padding-omitted). If the roster size changes, the three count asserts are re-derived from the manifest and the re-derivation is part of the commit message, not silent.

## Plan Pressure Test

Owner fit good (`gen_specs.py` already owns template selection and body synthesis). No new dependency, no new fixture, no network. Steps are sequential (manifest → emit → gates) but each step is independently verifiable; the gate command is the whole surface.

---

## Task 1: Era table in the generator

**Files:**
- Modify: `crates/leas-tls/src/fingerprints/catalog/gen_specs.py`

**Interfaces:**
- Internal: `synthesize_wire(entry)` gains an era lookup; `_template(...)` stays the value carrier, gains era parameters (no public Rust API changes).

**Steps:**
- [ ] **Step 1: Add the era lookup.** Per the grilled decision (generator table keyed by browser major, runtime clamp rejected, deferral rejected), add a small era table next to `FAMILY_TEMPLATES` keyed by template-family + browser major, with intervals:
  - `chrome_desktop` `>= 131`: groups `[0x11EC, 0x001D, 0x0017, 0x0018]`, key_share `["X25519Mlkem768", "X25519"]` (the current template, correct for ≥131).
  - `chrome_desktop` `124 <= major < 131`: pre-standard `X25519Kyber768Draft00` (0x6399) **only if the corpus row attests it**; otherwise X25519-only and the row is `low_fidelity` (never upgraded to a real-browser claim).
  - `chrome_desktop` `< 124`: groups `[0x001D, 0x0017, 0x0018]`, key_share `["X25519"]` — no PQ, matching the eras Kimi correctly flagged (Chrome 89-115, Opera 97-98).
  - Per-family PQ rows (`firefox >= 132` per the crawlex anchor, Safari later/post-OS): same low-or-attest rule; today the firefox/safari templates have no ML-KEM, so this step is a no-op for them until attested.
  - `key_share groups ⊆ supported_groups` and IANA-assigned codepoints are asserted in `--selftest` (so `0x1304` can never emit again).
- [ ] **Step 2: Run the selftest.** `python3 gen_specs.py --selftest` — expects green with the era intervals accepted and 0x1304 rejected.

**Acceptance:** every wire body for a `< 131` chromium row carries X25519-only groups/keyshare; `--selftest` green; no JA4 registered value changes (JA4 does not hash key_share bodies).

## Task 2: 0x0032 gate + template body cleanup (D4, D3)

**Files:**
- Modify: `crates/leas-tls/src/profiles/mod.rs` (`MIN_BODY` table)
- Modify: `crates/leas-tls/src/fingerprints/catalog/gen_specs.py` (`synthesize_wire` / templates)

**Steps:**
- [ ] **Step 1: Close the gate hole.** Add `(0x0032, 2, "signature_algorithms_cert")` to `MIN_BODY` (`profiles/mod.rs:433-444`). Emission is already non-empty (`gen_specs.py:545-553`), so this is a regression gate, not a shape change.
- [ ] **Step 2: Drop non-browser template extensions from emitted rows.** Remove `0x0016` (`encrypt_then_mac`) and `0x0031` (`post_handshake_auth`) from emitted `exts:` lines for browser-family rows when the corpus capture does not carry them. Real clients (Chrome/Firefox/Safari) never send either; the encoding is RFC-legal (erratum K2) but the *template* is wrong. Keep `EMPTY_BODY_OK`/`EMPTY_BODY_ILLEGAL` codec paths in the generator (tests and Exo-extension carriers still need them). This is a template-sanity change, not a well-formedness fix.
- [ ] **Step 3: Run the selftest + build.** `python3 gen_specs.py --selftest`; `cargo build -p leas-tls` — both green.

**Acceptance:** no emitted row carries `raw[0x0016, ""]`/`raw[0x0031, ""]` unless the corpus row itself carries the id; the 0x0032 MIN_BODY entry exists and fires.

## Task 3: Regenerate + fix the hardcoded counts

**Files:**
- Regenerate: `crates/leas-tls/src/fingerprints/catalog/specs_manifest.json`, `crates/leas-tls/src/fingerprints/catalog/catalog_data.rs`, `crates/leas-tls/src/profiles/generated/*.rs`
- Modify: `crates/leas-tls/src/profiles/mod.rs` (`GENERATED.len()`), `crates/leas-tls/tests/generated_ja4_gate.rs` (69/49/16/4/3 asserts), `crates/leas-tls/src/fingerprints/catalog/gen_specs.py` (`KEPT_STATS`)

**Steps:**
- [ ] **Step 1: Regenerate in the documented order.** `python3 gen_specs.py --manifest` **first**, then `python3 gen_specs.py --emit` (module docstring `:28-40` — `--emit` alone reverts any body fix; this is the documented failure mode, not a suggestion).
- [ ] **Step 2: Re-derive counts from the manifest.** If the roster size changed (era demotions, fingerprint-less rows), update `profiles/mod.rs:384`, `generated_ja4_gate.rs:238-261`, and `gen_specs.py:873-907` (KEPT_STATS) from the re-derived manifest numbers; record the derivation in the commit message.
- [ ] **Step 3: Run the full gate.** `python3 gen_specs.py --selftest`; `cargo nextest run -p leas-tls` (JA4 gate green, `len == N` updated); `cargo clippy --workspace --all-targets --all-features -- -D warnings` green.

**Acceptance:** Ja4 gate 69/69 (or the re-derived count) reproduced; committed files == fresh render byte-for-byte; all counts come from the manifest.

## Task 4: Docs sync

**Files:**
- Modify: `docs/reference/tls-fingerprint-roster.md` (if counts or low_fidelity numbers changed)
- Modify: `docs/architecture/decisions.md` (only if a durable decision was made — the era table is; the docstring comment already documents the corpus semantics split)

**Steps:**
- [ ] **Step 1: Update the roster doc counts** (69 → re-derived N; the §25-29 "69 → 18 distinct JA4s" sentence if N changed).
- [ ] **Step 2: Add an ADR/data note** recording the era table boundaries and the FoxIO-keyed JA4 per S3 pre-work (the decision already made at the grill, now on record).

**Acceptance:** docs match the regenerated roster; `docs/INDEX.md` needs no new entry unless a new doc is created (a note inside existing docs is preferred).

---

## Execution notes (2026-11-05)

**Landed.** Era axis (`PQ_ERA` + `_era_groups_keyshare` in `gen_specs.py`), the `0x0032`
`MIN_BODY` entry (`profiles/mod.rs`), regeneration of `specs_manifest.json` +
`profiles/generated/chrome.rs`. Roster membership is unchanged at **69 generated /
71 kept**; the manifest delta is 627 rows × 2 lines, exactly the `4588` group id and
`"X25519Mlkem768"` key-share removal.

**Gate evidence.** `gen_specs.py --selftest` PASS; `cargo nextest run -p leas-tls`
258 passed; `cargo nextest run --workspace` **2629 passed (3 slow), 11 skipped**;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean. The
offline JA4 gate re-derived only one class: padding-omitted 4 → 0, padding-in-hello
16 → 20 (pre-124 hellos no longer carry the 1.2 KB key share, so none reaches the
512-byte padding target). Full 49 / no-sig 0 / `ht` 3 / failures 0 are unchanged.

**Withdrawn during execution.** A `0x1304`-is-unassigned premise led to a row-drop
and an `IANA_CIPHERS` allowlist; both were reverted. `0x1304` is
`TLS_AES_128_CCM_SHA256` (RFC 8446 B.4; `thirdparty/utls/dicttls/cipher_suites.go:160`),
so the codepoint is assigned and `brave_89`/`brave_90` belong in the roster. The real
limitation is engine support — `crypto/mod.rs:1087` asserts
`CipherSuiteId::from_u16(0x1304) == None` — which is out of S1 scope.

**D3 reversed.** `raw[0x0016, ""]` / `raw[0x0031, ""]` stay when the corpus row
carries them: the ids are RFC-legal empty bodies and removing them is a roster-identity
change (extension count + hash2), not a body fix.

**Residual gap (accepted for S1, recorded rather than implicit).**
`crates/leas-native/examples/amiabot_sweep.rs:63-72` iterates the 69 `GENERATED`
rows plus the 2 hand profiles and drives the live engine against them. Examples are
not test targets, so no test executes that iteration: the era change's effect on the
sweep path is covered by **compile + the offline JA4 gate only**, not by execution.
Proving "the era rows still connect" needs a new hermetic test (or a tier-2 sweep
run), which is deliberately not part of S1.

**Not run.** Live `grader --roster` against `tls.peet.ws` (network, tier-2, not a
gate), so the padding-omitted → 0 shift is inferred from the offline gate rather
than observed on the wire.

---

## S2 (same plan file): GREASE-ify the generated roster

**Landed.** `chrome_desktop` / `chrome_android` templates gained `grease=True`;
`synthesize_wire` prefixes the GREASE cipher, emits the standalone GREASE
extension, and injects GREASE into `supported_groups`, `key_share` and
`supported_versions`. Firefox, Safari, Safari-iOS, okhttp and fallback stay
GREASE-free. Regenerated: 38 `grease` tokens in `chrome.rs`, 43 in
`chrome_android.rs`, 0 elsewhere.

**Gate evidence.** `gen_specs.py --selftest` PASS; offline JA4 gate unchanged at
`total=69 full=49 padding-in-hello=20 padding-omitted=0 no-sig=0 ht=3` — GREASE
moving nothing is the point. `cargo nextest run -p leas-tls` 258 passed;
`cargo nextest run --workspace` **2629 passed (1 slow), 11 skipped**;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean;
`cargo build -p leas-native --example amiabot_sweep` compiles against the new
roster.
`all_profiles_build_and_parse` now asserts the family split in both directions,
scoped by template family (iOS rows are Safari-shaped despite a Chromium brand).

**Not done.** No golden wire comparison against a recorded Chromium capture —
no capture exists in this checkout, and the JA4 gate plus the family invariant
are the verifiable substitutes. Recorded as a gap, not claimed as done.

**D5 exposure, measured.** A throwaway probe (built every roster row under the
`0x5A` fixture, compared GREASE extension-id counts, then deleted) found the
duplicate-extension-type state in **`edge_106` only** — two standalone `grease`
slots both drawing `0xAAAA` — and **zero** occurrences across all 69 generated
rows. So S2 does not widen the defect; the one-slot-per-namespace shape keeps
the fixture clean. The dedup gate was nonetheless tightened: it now asserts zero
duplicate extension ids for generated rows (GREASE included) and exempts only
the hand rows, with `edge_106`'s second slot named as the D5 reason. Fixing
`draw_grease_distinct` itself stays S4.

---

## S3: JA4 variant parameterization + encoder fixes

**Landed.** `Ja4Variant { Foxio (default), PeetWs }`; FoxIO keeps `0x0015` in
`hash2` and GREASE-filters sig-algs, PeetWs reproduces the previous pin exactly.
A-part derives the version from `supported_versions` (new u8-length reader —
the generic u16 reader mis-parsed its body) and `d`/`i` from SNI; ALPN follows
the FoxIO table incl. the hex fallback; empty lists render `000000000000`.
`sigalgs[grease]` is drawn per connection (`encode_signature_algorithms_into`
+ the `spec_has_grease` arm), proven by a test that asserts the `0xCACA`
sentinel never reaches the wire. `ja3_grease_stripped` now strips GREASE from
`curves`; classic decimal/dash JA3 (`ja3_classic_string`/`ja3_classic_hash`)
sits beside the historical hex rendering.

**Oracle.** The FoxIO published example (`t13d1516h2_8daaf6152771_e5627efa2ab1`)
is asserted as a real vector, together with its `6d807ffa2a79` no-sig variant,
the peet variant's `f37e75b10bcc`, and the ALPN table rows.

**Gate movement (expected).** Offline gate `full-hash 49 → 66`, `ht-letter 3`,
everything else 0: the 46 former padding-in-hello rows now hash identically, and
the 3 `ht` rows differ only in the corpus's `http/1.1` → `ht` letter.
Hand-profile pins moved from `…f37e75b10bcc` to `…e5627efa2ab1`.

**Semantics note.** `resolve::in_catalog` compares against the corpus, so under
the FoxIO default the hand rows' JA4 now genuinely is a corpus hash; the test
asserts agreement with `catalog::contains` instead of a hardcoded `false`.

**Peet test encoder de-duplicated.** `tls_peet_ws::local::ja4_v2` now composes
the crate's `hash1` + `hash2_variant(PeetWs)` (removing a ~50-line fork that
hardcoded `t13d` and could drift from `ja4_a`); only `peet_a_part` stays local,
because the live server genuinely deviates there (unpadded decimal counts, no
`00` letter). Its `CHROME130_JA4` pin remains the peet rendering, and the doc
comment now says why it differs from `tests/fingerprints.rs`'s FoxIO pin for the
same profile.

**Spec note.** `sigalgs[grease]` draws from `grease_a` — the extension-body
pairing value shared with the first cipher/group/version/key-share slot — not a
fresh per-namespace value; latent, since no shipped profile uses it.


---

## S4: builder hardening (D5, D6, D10)

**D5 — `draw_grease_distinct` is a hard error.** After 8 collisions it returns
`TlsError::Crypto` instead of the last (duplicate) value. New test: two GREASE
extension slots + constant RNG ⇒ typed error, no hello emitted. The roster
tests' fixture changed from flat `0x5A` (which collapses every draw to
`0xAAAA`) to a nibble-cycling sequence, because `edge_106` has two standalone
GREASE slots and now legitimately needs distinct draws.

**D6 — ECH payload length is spec-configurable.** `ExtensionSpec::EchGrease`
gained `payload_len: Option<usize>` with DSL form `ech[N]`; `build_hello` sizes
the payload from it, `ECH_PAYLOAD_LEN = 144` stays the default. This beat a
`BuildParams` field, which would have required 31 literal edits for a knob no
profile varies. New test builds `ech[200]` and reads the encoded payload length.

**Gate evidence.** `cargo nextest run -p leas-tls` 270 passed;
`cargo nextest run --workspace` **2641 passed (1 slow), 11 skipped**;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
The 2635 → 2641 delta is exactly the six tests this slice added (D5 hard error,
D6 `ech[200]`, four D10 negative cases), so nothing was silently skipped.

**D10 — parser negative coverage.** `hello_with_lengths()` + an `#[rstest]`
table assert oversized `cs_len`, `ext_total` and per-extension `len` are all
`TlsError::Handshake`; a fourth case pins the 24-bit handshake-length overflow.
No parser logic changed (it was already bounds-checked).


---

## S5: HTTP/2 + navigation profile coupling

**Landed.** New `leas_tls::Http2Profile` (`for_browser`, `for_identity`,
`settings`) is the single SETTINGS/UA/`Accept` table; `Resolved::http2_profile()`
derives it from the resolved identity, with iOS rows Safari-shaped regardless of
brand. `SpiderConfig` gained `browser`, set from the configured fingerprint in
`leas-native`, and the spider now builds its navigation headers from the profile
— the documented "Firefox hello + Chrome UA" mismatch. `leas-native::headers::
h2_settings` delegates to the profile instead of duplicating the numbers.
Tests: family divergence (settings × UA), Chromium-brand collapse, iOS ⇒ Safari,
and the spider's UA/header set.

**Deliberate non-change.** `transport/http/conn.rs`'s h2 clients (v2rayhttp,
xhttp) keep hyper defaults: they carry proxy protocol traffic, not browser
navigation. Browser-shaping them would introduce a new tell.

**Gate evidence.** `cargo nextest run -p leas-tls` 275 passed;
`cargo nextest run -p leas-native` 714 passed;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.


---

## S6: REALITY eligible-random picker

**Graft investigated first (the grilled precondition).** `chrome_130_hybrid_spec`
grafts `0x11EC` onto a Chrome-130 identity, but the standardized hybrid shipped
in Chrome 131 (130 carried draft `0x6399`), so the graft describes a wire no
Chrome 130 emitted — the S1 anachronism class, in the hand path. xray's REALITY
server only logs whether the share is hybrid (`reality.go:104`), so PQ is not a
protocol requirement. Decision: exclude the graft; the pool is the raw roster.

**Landed.** Predicates on `ClientHelloSpec` (`supports_tls13_aead`,
`session_id_wire_len`, `offers_x25519_key_share`, `offers_mlkem_hybrid`,
`reality_eligible`); `reality_candidates()` (46 rows: 44 generated + 2 hand);
`random_reality_spec(rng)` (8 RNG bytes, uniform index); `RandomEligible`
provisioner delegating the session-id-only transform to `SpecProvisioner`;
`HelloProvisionerChoice::RandomEligible` in `leas-native`.

**Tests.** Every candidate is REALITY-eligible, names are unique, and 32 seeded
picks all land on eligible rows (the pick cannot return a non-candidate).

**Gate evidence.** `cargo nextest run -p leas-tls` 277 passed;
`cargo nextest run -p leas-native` (with leas-tls) 991 passed;
`cargo nextest run --workspace` **2648 passed (1 slow), 11 skipped**;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.

**Not wired.** No user-facing config selects `RandomEligible` yet — the variant
is reachable programmatically; exposing it through `fp`/config syntax is a
separate decision (it changes what a REALITY dial looks like to the server).


---

## S7: family- and era-scoped extension permutation

**Landed.** `hello::build_hello_ordered(spec, params, permute)`; `build_hello`
delegates with `false`. `handshake::connect_with_permutation` threads the flag
into the first hello and the HRR replay (`RetrySupport::permute_extensions`), so
a rebuilt `ClientHello2` re-permutes from replayed draws rather than diverging
silently. `client::permutes_extensions` decides from the resolved identity:
Chromium brands at major ≥108 shuffle, Firefox's default build and Safari do
not. `permuted_order` = Fisher–Yates (4-byte draw per swap) with padding last
and `pre_shared_key` last-of-all.

**Design choice.** A handshake flag, not a `ClientHelloSpec` field: the flag
belongs to the identity (browser + major), and a spec field would have churned
every struct literal for information the roster does not carry.

**Tests.** Two connections produce different orders; padding stays last; the
non-GREASE extension set is identical; unpermuted builds keep spec order; and the
policy table covers Chrome 108 (permute) / 107 (no), all Chromium brands,
Firefox 150 / Safari 26 (no), and the resolved-major-wins case.

**Gate evidence.** `cargo nextest run -p leas-tls` 280 passed;
`cargo nextest run --workspace` **2651 passed (1 slow), 11 skipped**;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.

**Caveat.** Real Chromium also permutes `supported_versions`/key-share ordering
inside extension bodies? No — permutation is extension-block order only; body
internals stay. Note that HRR replays re-run the same permutation draws, so the
retry stays byte-comparable to the first hello apart from `key_share`/`cookie`.
