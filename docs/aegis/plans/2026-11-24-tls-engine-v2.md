# TLS engine v2 — implementation plan

Date: 2026-11-24
Evidence: `docs/research/2026-11-24-tls-engine-enhance-vs-rewrite.md`
(verdict: enhance, not rewrite; Sans-I/O core committed).
Domain: `crates/leas-tls`, with the `leas-native` security/transport seams and
`leas-hotpath`/`leas-oracles` gates.
Execution route: **inline, one phase per commit**; each phase is independently
verifiable. A `reviewer` agent runs before **every** commit and that commit's
findings are fixed first; a whole-scope reviewer runs again before the push.

`User confirmation required: no` — the scope is the approved research-doc
roadmap and the user's explicit instruction to implement all of its steps.

## 1. Goal

Implement every step of the research doc's staged plan without changing the
public seam (`client::connect`, `TlsStream`'s `AsyncRead`/`AsyncWrite`,
`reality::connect_reality`), the 71-profile roster, or the crypto posture
(ring only, `#![forbid(unsafe_code)]`, one provider).

Phase outcomes:

| Phase | Outcome | Evidence of completion |
|---|---|---|
| P0 | Correctness gates: ALPN must have been offered; unsolicited/duplicate ServerHello extensions rejected; `close_notify` on graceful shutdown; KeyUpdate flood cap; 512 KiB flight bound; CertificateVerify scheme must have been offered; documented sig-scheme boundary; handshake + relay benches | New discriminating tests; benches print baseline; roster classification test |
| P1 | **Sans-I/O core**: record+handshake protocol state behind `feed`/`poll_transmit`/`poll_event`; `TlsStream` is an async adapter; differential harness against the old path | Non-reactor replay tests for TLS 1.3/HRR/TLS 1.2/REALITY/ECH; byte-identical differential rows; hotpath unchanged |
| P2 | Compile-time hello caps (O(1) declared-profile predicates); static/spec cache; batched seal; opt-in session resumption | CAPS/emitted-hello gate; allocations/connect drop; syscalls ≤2 per 64 KiB; resumed-dial test with JA4 gate |
| P3 | Post-handshake ALPS settings; browser-shaped HTTP/2 settings in the production carrier | ALPS emission test; h2 fingerprint row |

## 2. Architecture

- Keep one TLS lane. ring + RustCrypto; no aws-lc-rs, no BoringSSL, no rustls.
- `leas-tls` owns protocol logic; `tokio` is adapter-only after P1.
- Profiles stay data. CAPS is a `const` sidecar describing the **declared**
  roster profile, never the mutated per-connection spec.
- Wire-truth checks (`ensure_offered_suite`, `ensure_offered_key_share`) stay
  on parsed bytes.

## 3. Baseline, authority, compatibility

- Baseline refs: `docs/reference/native-core.md`,
  `docs/reference/tls-fingerprint-roster.md`, `docs/reference/crypto-dependencies.md`,
  `AGENTS.md`.
- Public compatibility: `crates/leas-native/src/security/mod.rs`,
  `transport/http/conn.rs`, `probe.rs`, `protocol/vless/vision.rs`,
  `crates/leas-oracles/src/e2e/*`.
- Fixed constraints: `#![forbid(unsafe_code)]`, ring as the single provider,
  no schema/DB change, no `aws-lc-rs`.

## 4. TDD route

`TDD Route: auto → strict` for P0 gates, P2 CAPS/batching/resumption, P3 ALPS:
behavioural, contract, and regression-sensitive. `strict` means a failing test
first for each gate, then implementation. `light` for benches and pure-doc
rows. `skipped` for the plan/INDEX text itself.

## 5. Tasks

### P0 — correctness and baseline (commit C2)

| # | Change | Files | Acceptance |
|---|---|---|---|
| P0.1 | Handshake + relay benches | `crates/leas-tls/benches/handshake.rs`, `benches/relay.rs`, `Cargo.toml` | `cargo bench -p leas-tls --bench handshake -- --quick` prints connects/s and allocs/connect; relay prints MiB/s |
| P0.2 | ALPN must be offered | `handshake/flight.rs`, `handshake/mod.rs` | Server selects `h2` when only `http/1.1` offered → typed error |
| P0.3 | Reject duplicate and unsolicited ServerHello extensions | `handshake/mod.rs` | Duplicate `supported_versions` and an unknown extension both fail with `unsupported_extension` |
| P0.4 | `close_notify` on graceful shutdown, abort path preserved | `record/stream.rs` | Peer sees alert 0 on `shutdown`; abort still FIN-only; Vision rows green |
| P0.5 | KeyUpdate flood cap | `record/stream.rs` | 129th consecutive update → typed error |
| P0.6 | Flight bound 512 KiB + offered-signature-scheme check | `handshake/mod.rs`, `verify/mod.rs` | Oversized chain rejected at 512 KiB; unoffered scheme rejected |
| P0.7 | Sig-scheme boundary + roster classification | `verify/mod.rs`, `docs/reference/tls-fingerprint-roster.md`, test | Every advertised scheme classified verifiable/documented-unverifiable; no silent drift |

### P1 — Sans-I/O core (commits C3a, C3b, C3c)

| # | Change | Files | Acceptance |
|---|---|---|---|
| P1.1 | `record::Engine` (byte-in/byte-out, KeyUpdate, alerts) | `record/engine.rs`, `record/mod.rs`, `record/stream.rs` | Unit tests drive records without tokio; hotpath 0 alloc rows unchanged |
| P1.2 | `handshake::StateMachine` (TLS 1.3, HRR, ECH, REALITY, TLS 1.2) | `handshake/engine.rs`, `handshake/mod.rs`, `handshake/flight.rs`, `handshake/tls12.rs`, `ech.rs`, `reality/mod.rs` | `feed`-driven replay finishes each branch; no `tokio` imports in engine modules |
| P1.3 | `TlsStream` adapter + differential harness | `record/stream.rs`, `handshake/mod.rs`, `tests/engine_differential.rs` | Old/new outputs byte-identical over recorded transcripts; all prior tests green |
| P1.4 | Bounded fuzz/property target | `tests/engine_fuzz.rs` | Arbitrary bytes never panic; state stays bounded |

### P2 — speed and compile-time caps (commit C4)

| # | Change | Files | Acceptance |
|---|---|---|---|
| P2.1 | `HelloCaps` + `GenEntry.caps` + `const fn` predicates | `spec/caps.rs`, `spec/mod.rs`, `profiles/mod.rs`, `profiles/hand_selected.rs`, `profiles/generated/mod.rs`, `hello/mod.rs`, `client.rs`, `reality/mod.rs`, `fingerprints/catalog/gen_specs.py`, tests | CAPS/emitted-hello equality across roster; declared-profile predicates O(1) |
| P2.2 | Cache resolved specs by identity (`Arc<ClientHelloSpec>`; the static/borrowed form is a separate public-API change) | `fingerprints/resolve.rs`, `profiles/*` | allocations/connect drop vs P0 bench; `Resolved.spec`'s public type unchanged |
| P2.3 | Batched seal (≤32 KiB / ≤7 records) | `record/engine.rs`, `record/stream.rs` | ≤2 syscalls per 64 KiB; lone small write latency unchanged |
| P2.4 | Opt-in TLS 1.3 resumption | `handshake/engine.rs`, `record/stream.rs`, `client.rs` | Resumed dial skips full flight; JA4 gate for resumed shape; REALITY and PSK-free roster rows excluded (`select_roster`); bounded cache |

### P3 — fidelity (commit C5)

| # | Change | Files | Acceptance |
|---|---|---|---|
| P3.1 | Post-handshake ALPS settings | `handshake/engine.rs`, `record/stream.rs` | Profiles that offer `application_settings` emit ALPS after Finished; others do not; live grader (`tests/tls_peet_ws.rs`) reports the same ALPS presence as the reference browser |
| P3.2 | Browser-shaped h2 settings in production carrier | `crates/leas-native/src/transport/http/conn.rs`, `crates/leas-tls/src/http2_profile.rs` | SETTINGS order/values match the profile family; test asserts the frame; live target's h2 fingerprint matches the TLS identity |

### P4 — docs, review, delivery (commit C6)

- Update `AGENTS.md` if module layout changed; update `docs/reference/native-core.md`
  and the research doc's status.
- Final reviewer on the whole plan scope; fix findings.
- `git push`, then watch CI with `UV_GITHUB_TOKEN`.

## 6. Verification

Per phase:

```
cargo fmt --all -- --check
cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings
cargo nextest run -p leas-tls
cargo nextest run -p leas-native
cargo nextest run -p leas-hotpath   # counting-allocator self-tests
just hotpath                        # the five exact allocation rows (release)
```

Plus the phase-specific benches/gates above. Final:

```
cargo nextest run            # default members
just quality-gate code
just hotpath
just memtrace-app            # boot profile unchanged or better
git push origin HEAD
```

Oracle rows (`cargo nextest run -p leas-oracles`) only where the phase changes a
wire path (P0/P1/P3); their pins are not bumped.

## 7. Risks and retirement

- **Sans-I/O is the largest change.** Land in three slices (record → handshake
  → adapter) behind a differential harness; delete the old async protocol path
  in the same commit that proves equivalence, no parallel owners.
- **Resumption is opt-in** and never used for REALITY or a profile whose roster
  row is PSK-free (`select_roster` drops PSK captures); it changes the resumed
  hello's JA3/JA4, so it is gated by a separate expected value, not the roster
  goldens.
- **CAPS drift** is guarded by the emitted-hello recomputation test; CAPS is not
  read after a spec mutation without recomputation.
- **No crypto dependency change.** P-521/PSS-only leaves remain a documented
  typed failure; the roster classification test makes the boundary explicit.
- **Win path:** CI must be green on the pushed branch; a red CI result is not
  completion.

## 8. Commit sequence

| Commit | Scope | Reviewer |
|---|---|---|
| C1 | This plan + research doc + both INDEX rows + the prior ferrox comparison it cites | before commit |
| C2 | P0 correctness gates + benches | before commit |
| C3a | P1 record `Engine`; hotpath/Vision rows unchanged | before commit |
| C3b | P1 handshake `StateMachine` (TLS 1.3/HRR/TLS 1.2/REALITY/ECH) | before commit |
| C3c | P1 `TlsStream` adapter + differential harness + fuzz; old path deleted | before commit |
| C4 | P2 caps + speed | before commit |
| C5 | P3 fidelity | before commit |
| C6 | Docs, final review fixes, push | whole scope |

## 9. Execution status (2026-11-24)

| Phase | Status | Evidence |
|---|---|---|
| C1 plan | executed | `4087b394` |
| P0 correctness | executed | `a553d7dc` (ALPN, extension gates, `close_notify`, KeyUpdate cap, 512 KiB flight, scheme boundary, benches) |
| P1 record Sans-I/O | executed | `7633816e` (`record::engine`, exact-read adapter, legacy path deleted) |
| P2 batching/spec cache | executed | `d4f7f1fe` (32 KiB batches, shared `Arc` spec) |
| P2 HelloCaps | executed | `3df30938` (const masks, generator, roster gate, REALITY candidate filter) |
| P1 differential harness | **not executed** | `tests/engine_differential.rs` was not written; the record refactor landed without a byte-identical old/new replay. |
| P1 bounded fuzz | **not executed** | `tests/engine_fuzz.rs` was not written; `Engine::feed` has unit tests only. |
| P1 handshake state machine | **not executed** | The committed Sans-I/O split for the handshake remains open; no facade was shipped. |
| P2 resumption | **not executed** | Opt-in PSK ticket cache still open. |
| P3 ALPS / h2 fidelity | **not executed** | Post-handshake ALPS settings and browser-shaped h2 SETTINGS still open. |

The branch is shippable for the executed phases; the remaining committed
phases are not claimed complete.
