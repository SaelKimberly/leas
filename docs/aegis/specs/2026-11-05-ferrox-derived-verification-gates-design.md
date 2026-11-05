# Design: Verification gates borrowed from `thirdparty/ferrox` — byte oracles, freshness, leak/fixture gates

- **Date:** 2026-11-05
- **Status:** **draft — awaiting approval.** Read-only audit; no code touched.
- **Kind:** spec
- **Owners:** `crates/leas-tls/tests/**`, `crates/leas-native/tests/**`, `justfile`, `.github/workflows/ci.yml`, new `scripts/gates/*.sh`
- **Evidence base:** `thirdparty/ferrox` @ `188d80d`: `scripts/*-oracle/**`, `scripts/{count-ops,check-*}.sh`, `crates/ferrox-bench/**`, `.github/workflows/*.yml`; compared against leas's tiers in `docs/reference/native-core.md:116-193` and `justfile`.

## 0. The one sentence that matters

leas's tier-1 gate proves the encoder and the decoder in this repo agree with each other. Ferrox's oracles prove its bytes agree with **pinned upstream Go source**. That difference is exactly the class of bug that surfaced twice in this audit — our own `option = 0` VMess body and our advertised-but-unservable CBC suites — both invisible to a round trip, both visible to a golden from the reference implementation.

## 1. Witness verdicts — what ferrox's harness actually is

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| V1 | Each oracle drives **pinned reference source in-process**, not a socket and not a binary under test; the output is raw octets committed as a golden and `include_str!`-ed by a Rust test | **CONFIRMED** | `socks5-oracle/main.go:73-116` (xray `socks.ClientHandshake` over `bytes.Buffer`) replayed at `crates/ferrox-core/src/socks.rs:443-479`; `dns-oracle/main.go:152-157` → `dns.rs:463-464`; `httpupgrade-oracle/main.go:52-90` → `ferrox-app/src/httpupgrade.rs:1202-1203`; `kcp-oracle/main.go:30-33` → `ferrox-core/src/kcp/oracle.rs:95-96`; `utls-oracle/main.go:1-13` (entropy zeroed before printing) → `tls/shaped/hello.rs:1327-1328`; `tls12-oracle/main.go:1-6` → `shaped/oracle.rs:260-261`, `:334-335`. Nine oracle directories in total. |
| V2 | The goldens have **no freshness gate** — regeneration is prose | **CONFIRMED — this is the defect to not inherit** | No workflow references `oracle`/`expected.txt` (workflow grep: zero hits). The ritual is documented in prose only (`docs/function/carrier-httpupgrade.md:78`). `scripts/check-upstream-pins.sh:96-105` proves the *rev resolves*, never that the golden still equals what that rev prints. A pin bump that changes reference output is invisible. |
| V3 | `count-ops.sh` (exact retired-instruction rows) is a **real** measurement but an unusable gate | **CONFIRMED** | Real: `scripts/count-ops.sh:5,8,78-79` (valgrind required, line tables forced), `:63-70` refuses to profile a filter that matches no test, `:140-181` refuses a broken profile. Unusable as a portable gate: rows move ±13 Ir when an *unrelated test* is added to the same binary (`scripts/expected-ops.txt:17-42`, eight re-blesses recorded), it needs a pinned valgrind+glibc userspace (`ops.yml:48-58`), and it **never runs on a PR** (`ops.yml:3-4` dispatch-only; `check.sh:172-177` skips on macOS; `ci.yml:36-45` has no counts step). |
| V4 | `method-counts.txt` / `method-ops.txt` bookkeeping has no teeth | **CONFIRMED** | `check-method-docs.sh:86-95` compares free text; `ops.yml:112-115` states the ops report can never red. 114 KB of manifest whose only enforcement is that two human-edited files agree. |
| V5 | The matrix + gap allowlist mechanics are sound even though we do not want the matrix | **CONFIRMED** | `scripts/check-matrix-legs.py:176-186` (a leg worse than its filed ratio by > 0.10 fails), `:571-578` (a leg that stops gapping warns to be deleted), allowlist format `scripts/leg-gaps.txt:1-4`. 39 filed gaps already — the mechanism works, the corpus is what costs. |
| V6 | leas owns a freshness mechanism that nothing calls | **CONFIRMED** | `crates/leas-tls/src/fingerprints/catalog/gen_specs.py:1296` `_selftest()` (verifies committed == fresh render), reachable as `--selftest` (`:1484`, `:1493`). No `justfile` recipe and no workflow invokes it (`grep selftest justfile` → zero; `ci.yml` has one job for the `code` gate). |
| V7 | leas's tier-3 harness fails loudly rather than skipping green | **CONFIRMED — already correct, no work** | `crates/leas-native/src/e2e/core.rs:32-70` returns `Err` for an unset `LEAS_CORE_BIN_DIR`, a missing binary, and a version mismatch. The rows are feature-gated (`native-e2e`), which is a *visible* opt-in, not a silent skip. |

## 2. Gaps this spec closes

| Rank | Gap | Consequence | Class |
|---|---|---|---|
| 1 | No wire golden from a reference implementation; tier 1 is self-consistent | The audit found two wire defects (`vmess/header.rs:96`, the CBC advertisement set) that no existing test could see. | evidence |
| 2 | `gen_specs.py --selftest` unwired | The roster can drift from its generator silently — the exact failure ferrox suffers with its oracle goldens. | evidence |
| 3 | No leak-surface gate | Nothing stops a `println!`/`eprintln!` or a wall-clock read from entering a core crate; the TUI is the only intended sink. | hygiene |
| 4 | No fixture-safety gate | Test fixtures in this repo are **real configs from user bug reports**; a committed `vless://uuid@host` or a routable IP is a live credential. | security |

## 3. Decisions

- **D1 — adopt the oracle pattern, invert its weakness.** One directory per wire surface under `crates/<crate>/tests/goldens/<surface>/` containing `oracle.go`, `go.mod` (pinned to `thirdparty/Xray-core` by relative `replace`), `generate.sh`, and `expected.txt`. The Rust side `include_bytes!`s the golden. **Plus** the freshness check ferrox lacks: `generate.sh --check` re-runs the oracle and diffs, and CI runs it. A golden that cannot be regenerated in CI is not evidence.
- **D2 — the oracle set is bounded to what a round-trip cannot see.** Five surfaces, one per slice: (a) VLESS request header + vision addon, (b) VMess AEAD header **with mask+pad** (the very defect that motivated this), (c) Trojan request + UDP frame, (d) Shadowsocks AEAD chunk framing (classic + 2022 header), (e) ClientHello bytes (owned by the TLS spec's S5 — one harness, two specs, no duplicate).
- **D3 — leak-surface and fixture-safety gates are adopted as CI steps, not as prose.** Both are greps with an allowlist and a **self-test that proves the gate fires** on a synthetic violation — ferrox's own unfired gates (`check-fixture-safety.sh`, `check-leak-surface.sh` have no selftest) are the warning.
- **D4 — `gen_specs.py --selftest` is wired into `just quality-gate` and `ci.yml`.** One line each; it already exists.
- **D5 — bench gap-allowlist mechanics are NOT adopted now.** No benchmark corpus, no runner, no need; the mechanism is recorded here so it is not re-derived later.

## 4. Slices

| Slice | Change | Gate |
|---|---|---|
| **S1** | Harness skeleton + VMess oracle (b) + VLESS oracle (a) | The golden is produced by pinned Go `thirdparty/Xray-core` code; the Rust test fails when our encoder drifts by one byte. `generate.sh --check` is invoked by CI. |
| **S2** | Trojan (c) + Shadowsocks (d) | Same shape; SS oracle covers classic AEAD and the 2022 fixed header. |
| **S3** | Freshness wiring (D4) + `just` recipes | `just quality-gate code` runs the roster selftest; a deliberately edited generated file fails it (proven by a temporary local edit, not committed). |
| **S4** | Leak-surface + fixture-safety gates with selftests (D3) | Each gate ships with a `--selftest` that runs it against a fixture containing one violation and asserts a non-zero exit. Without that, the gate is decoration. |
| **S5** | ClientHello byte oracle (D2e) | Owned by `2026-11-05-leas-tls-tls12-coherence-design.md` S5; listed here only so the harness is built once. |

## 5. Non-goals (and why)

- **`count-ops.sh` exact-instruction gating.** Moves for unrelated test edits, needs a pinned valgrind/glibc userspace, runs only on dispatch. Porting it buys a bless ritual, not a measurement.
- **`method-counts.txt` / `method-ops.txt` bookkeeping.** Free-text agreement between two files a human edits together; the ops column can never fail.
- **The 285-cell × 6-engine throughput matrix.** Six pinned Go/Rust trees and dedicated runners for a client TUI. leas benchmarks with criterion and tests against two cores; the gap-allowlist *mechanics* are recorded (D5) for when a corpus exists.
- **`check-comments.sh` / `check-method-superset.sh` as-is.** Style rules and a four-upstream catalogue that presumes trees we do not pin.

## 6. Verification plan

- Every gate added here must be observed **failing** once, on a synthetic violation, before it is accepted (`--selftest` is that observation made permanent).
- The oracle goldens must be regenerated from `thirdparty/Xray-core` at the pinned rev in the same commit that first adds them, so the diff that introduces a golden also shows its provenance.
- No existing test is modified by this spec.
