# TLS fingerprint roster — JA4 fidelity verification report (reduced roster)

**Date:** 2026-08-25
**Branch:** `native-core-stub` (JA4 roster reduction, Task 5)
**Roster:** 71 kept profiles = 69 generated JA4-faithful + 2 wire-exact hand
(`chrome_130`, `edge_106`)
**Live target:** `https://tls.peet.ws` (`/api/all`, TLS 1.3, HTTP/2 + HTTP/1.1)
**Result:** **71/71 PASS on both full runs** — every kept entry connected and
returned its expected JA4; the 2 hand profiles returned their hand-captured
JA4.

## Roster scale

| Module (`profiles/generated/`) | Entries | Wire template |
|---|---|---|
| `chrome.rs` (desktop Chromium: Chrome/Edge/Opera/Brave/Samsung) | 19 | `chrome_desktop` |
| `firefox.rs` (incl. Firefox for Android) | 9 | `firefox` |
| `safari.rs` (macOS/Windows WebKit) | 6 | `safari` |
| `chrome_android.rs` (Chromium Android) | 16 | `chrome_android` |
| `safari_ios.rs` (WKWebView reality — any browser on iOS) | 19 | `safari_ios` |
| **Generated total** | **69** | (fallback/okhttp families empty) |
| Hand (`profiles/hand_selected.rs`, `spec!`-declared wire-exact) | 2 | — |
| **Kept total** | **71** | |

The 69 generated entries are the deterministic `select_roster` subset of the
1825-entry manifest (top-3 distinct-JA4 clusters per browser/os/device triple,
family-range filtered, PSK excluded); they collapse to **18 distinct JA4s**.
The 2 hand profiles share one hand-captured JA4 absent from the corpus, so the
combined roster carries **19 distinct JA4s** and **0 pre_shared_key entries**.

Generator: `crates/leas-tls/src/fingerprints/catalog/gen_specs.py`
(`--manifest` → `specs_manifest.json` from the ja4db export; `--emit` →
`profiles/generated/*.rs`, byte-deterministic; `--selftest` verifies the
committed files match a fresh render of the kept subset).

## The 2 hand-upgraded slots

Per the design's wire-exact upgrade rule, a hand profile whose JA4 shares
A-part + hash2 with a kept cluster **and** whose triple equals the cluster's
triple replaces the top-ranked matching slot (one hand profile fills one slot):

| Hand profile | Triple | Replaces | Expected JA4 on tls.peet.ws |
|---|---|---|---|
| `chrome_130` | chrome / windows / desktop | `chrome_148_windows_desktop` | `t13d1516h2_8daaf6152771_f37e75b10bcc` |
| `edge_106` | edge / windows / desktop | `edge_149_windows_desktop` | `t13d1516h2_8daaf6152771_f37e75b10bcc` |

Both were transcribed byte-for-byte into `spec!` tokens from the original hand
modules (deleted; the equality was pinned by the removed
`hand_selected_matches_original_wire_bytes` equivalence test). They share the
same GREASE-normalized JA4 — `t13d1516h2_8daaf6152771_f37e75b10bcc` — which is
the **hand-captured** value, not the cluster's: it matches the #1 cluster
(`t13d1516h2_8daaf6152771_d8a2da3f94cd` / `…_02713d6af862`) in A-part, hash1
and hash2 and differs only in hash3 (signature-algorithms order — Edge 106
also carries two GREASE extensions to Chrome 130's one). The expected JA4 on
peet.ws for these slots is the hand-captured value, and the live sweep
confirms both return it exactly.

## Fidelity contract

Every kept entry's built `ClientHello` must reproduce its registered source
JA4 (`GenEntry.ja4`; for the hand profiles, the hand-captured value):

- **Offline gate** (`tests/generated_ja4_gate.rs`, runs in every
  `cargo test`): all 69 generated entries — 49 full-hash exact, 16
  padding-in-hello, 4 padding-omitted (512-byte target rule), 0 no-sig, 3
  corpus-`ht` entries, 0 failures. The 2 hand profiles are pinned offline by
  `tests/tls_peet_ws.rs::local_fingerprints_match_locked_constants`
  (chrome_130 JA4-v2 and GREASE-stripped JA3 md5 under the fixed seed) and by
  the resolver JA4-fidelity tests.
- **Live sweep** (`cargo run -p leas-tls --example grader -- --roster`):
  empirical confirmation against the real peet.ws API — this report. The
  grader walks the combined roster (`roster::combined_roster` = `GENERATED` +
  the 2 hand profiles).

## Live sweep — methodology

Each entry: `ClientHello` built from the spec with the fixed-seed fixture
(all-`0x5A`), parsed locally, then a real TLS 1.3 connection to tls.peet.ws
(per-connection GREASE via `SystemRandom`; JA4 is GREASE-normalized so the
fixed-seed local value is comparable). The server's reported JA4 is checked
against:

1. the local JA4 computed with the server's own algorithm (wire fidelity),
2. the registered expected JA4 (corpus value for generated entries,
   hand-captured value for the hand profiles — normalized for the server's
   rendering).

16 concurrent connections, 20 s per-entry cap. The server's `ja4.go`
rendering differs from the FoxIO spec in ways the grader replicates:

- A-part counts are **non-padded decimal** and the ALPN letter is **omitted
  when no ALPN is offered** (registered `t13d170900_…` is reported as
  `t13d179_…`);
- hash2 excludes the padding extension `0015` (already documented in the
  grader's reconciliation notes).

Entries whose hello offers no `h2` ALPN (the 3 `http/1.1`-only and 14
no-ALPN entries) are graded over an HTTP/1.1 GET (`Connection: close`,
Content-Length/chunked aware).

## Live results summary (2026-08-25, two full runs — identical)

| Family | Total | Full | Pad+ | Pad− | No-sig | `ht` | Wire-ok | Reg-ok | Fail |
|---|---|---|---|---|---|---|---|---|---|
| chrome (incl. `chrome_130`, `edge_106`) | 21 | 17 | 0 | 4 | 0 | 2 | 21 | 17 | 0 |
| chrome_android | 16 | 13 | 3 | 0 | 0 | 0 | 16 | 13 | 0 |
| firefox | 9 | 8 | 1 | 0 | 0 | 0 | 9 | 8 | 0 |
| safari | 6 | 5 | 1 | 0 | 0 | 0 | 6 | 5 | 0 |
| safari_ios | 19 | 8 | 11 | 0 | 0 | 1 | 19 | 8 | 0 |
| **TOTAL** | **71** | **51** | **16** | **4** | **0** | **3** | **71** | **51** | **0** |

- **71/71 entries (100%)** connected and matched the local JA4 (wire
  fidelity) in **both** runs; both hand profiles returned their hand-captured
  JA4 `t13d1516h2_8daaf6152771_f37e75b10bcc` — the hard gate.
- **0 deterministic rejections, 0 transient failures** across the two runs
  (the kept roster is PSK-free by construction, so the pre-reduction
  `0x0029` rejection class — see Finding 1 below — cannot occur).
- Reg-ok (51) counts the full-hash-class entries only: the pad+/pad−
  entries' registered corpus hash2 includes the padding extension while the
  server's `ja4.go` excludes it (the documented codec gap), so their
  registered-match flag stays clear by design — they are never failures.
- 54 entries speak HTTP/2, 3 are `http/1.1`-only (the `ht` entries), 14 offer
  no ALPN; 36 carry the ECH-GREASE outer extension.

## Findings

### Finding 1 — `0x0029` (pre_shared_key) exclusion (historical; no longer applies)

The pre-reduction roster had 111 entries carrying `raw[0x0029, ""]`; peet.ws
(Go `crypto/tls`) deterministically rejects any hello with it (fatal
`unexpected_message`), so those entries were live-connect-infeasible. The kept
roster **excludes PSK by construction** (`select_roster` drops `0x0029`
carriers), so no kept entry can hit this rejection — the sweep's zero-failure
runs confirm it. The sampled test keeps its PSK filter as a harmless guard.

### Finding 2 — empty bodies: the 2026-08-25 sweep's "accepted" verdict was wrong (fixed 2026-09-17)

36 kept entries carried the empty ECH GREASE outer (`fe0d`) and 28 carried an
empty `compress_certificate` list. Both connected and graded cleanly against
**tls.peet.ws**, and the sweep concluded they were fine because "the server
treats it as an unknown extension (RFC 8446 §4.2)" — true of that Go peer, and
false where it matters: `BoringSSL` (Cloudflare, Google — and the proxy hosts a
real batch talks to) parses `encrypted_client_hello` and `compress_certificate`,
and answers `alert 2 50 (decode_error)` to a body its RFC forbids.

Measured 2026-09-17: `alert 2 50` appeared on exactly the fingerprint ids that
resolve to those rows (firefox 37, ios 6, safari 4 of 3,380 phase-2 failures),
and an A/B on one link config with only `security.fp` swapped — same host, SNI,
ALPN — had `chrome`/`edge`/`randomized` complete the handshake while
`firefox`/`ios`/`safari` got `decode_error` in 0.1 s; six Cloudflare-fronted
hosts repeated it 6/6. Removing the extension from the resolved row made the
probe pass; removing the empty `compress[]` did the same for Safari.

The class is one emitter mistake repeated (`gen_specs.py` synthesizes bodies
from an id-only corpus): ALPS' body length (fixed 2026-09-16), ECH, the
compression list, `delegated_credentials`' sig-alg vector. Now:
`build_extension` names ECH to the engine's `EchGrease` variant (a body drawn
per connection — a constant body would give every connection of an identity
identical bytes), synthesizes the two sig-alg vectors like
`signature_algorithms_cert`, and substitutes `brotli` for an empty
`compress_certificate`; `_ext_token` **refuses** to emit a bodyless extension
whose id is in `EMPTY_BODY_ILLEGAL`, and
`profiles::tests::every_roster_hello_has_rfc_minimal_extension_bodies` sweeps
every emitted hello for each extension's RFC minimum. Tier 2's
`tests/strict_peer_presets.rs` is the live oracle for the class this doc's own
sweep could not see: a lenient peer grades a malformed body as clean.

(`pre_shared_key` `0x0029` is in `EMPTY_BODY_ILLEGAL` too — Finding 1 is
enforced at emit time now instead of relying on `select_roster` alone.)

### Finding 3 — `http/1.1`-only and no-ALPN entries (3 + 14)

- 3 `ht`-letter entries (brave_89_windows_desktop, brave_90_macos_desktop,
  firefox_138_ios_phone; ALPN `http/1.1` only): graded via the HTTP/1.1 GET
  path; the server renders the A-part letter `h1` (first+last, matching the
  crate codec). The corpus `ht` is the ja4db first-two-chars rendering — a
  documented A-part letter difference that keeps those entries'
  registered-match flag clear (they are never full-hash class, so it is not a
  failure).
- 14 no-ALPN entries: connect over HTTP/1.1 default; the server omits the
  A-part letter entirely and uses non-padded counts (see methodology).

### Finding 4 — 50 low-fidelity slots (JA4-faithful tier, by design)

At selection time **50 of the 71 slots were low-fidelity** — 48 of the 69 kept
generated entries are flagged `low_fidelity` in the manifest (their byte-level
wire shape — sigalgs ordering, extension bodies — is synthesized, not
observed; only their JA4 is corpus-faithful), plus the 2 upgraded slots
(`chrome_148_windows_desktop`, `edge_149_windows_desktop`) which were
low-fidelity generated entries replaced by wire-exact hand profiles. The 2
hand profiles are wire-exact (transcribed from real browser hellos); the
remaining 48 generated entries are **JA4-faithful**: they reproduce the
registered JA4 exactly (pinned offline and live) while their byte-level shape
may diverge from a real browser. This is the documented JA4-faithful tier —
JA4 reproduction is the contract, not byte-level wire mimicry.

### Finding 5 — dropped artifacts (historical)

- `chrome_619_windows_desktop` (spoofed-UA artifact, 35,850 corpus
  observations) and other out-of-range majors are excluded by the family
  sanity floors/caps (chrome 80–155, etc.) — see the design spec's range
  table.
- The empty-`0x0032` (`signature_algorithms_cert`) template bug found by the
  original 1825-entry sweep was fixed in the generator (synthesized RFC 8446
  §4.2.3 default body) and is gone from the regenerated roster.

## Reproduction

```bash
# Full live sweep over the kept 71 (69 generated + 2 hand), ~5 s
cargo run -p leas-tls --example grader -- --roster
# Per family / per (family, major)-band sample (hand profiles claim their band)
cargo run -p leas-tls --example grader -- --roster --family chrome
cargo run -p leas-tls --example grader -- --roster --sample
# Offline gate (no network; runs in every cargo test)
cargo test -p leas-tls --test generated_ja4_gate
# Offline hand-profile pins + sampled live test (one entry per family/band,
# incl. the hand profiles; ignored by default)
cargo test -p leas-tls --test tls_peet_ws
cargo test -p leas-tls --test tls_peet_ws -- --ignored
# Generator self-check (kept-set regeneration byte-deterministic)
python3 crates/leas-tls/src/fingerprints/catalog/gen_specs.py --selftest
```

The grader's `--roster` mode prints per-entry lines (`name family class ht ech
alpn server_ja4 error`) and a per-family summary (full / pad+ / pad− / no-sig
/ ht / wire-ok / reg-ok / fail). With `--sample` the wire-exact hand profiles
claim their (family, major) band first — `chrome_130` shares band 130 with the
generated `opera_130_*` entries — so the sample always covers them.
