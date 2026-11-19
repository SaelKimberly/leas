# Probe truth and the ingest boundary — implementation plan

Status: **executed 2026-11-19** (T1–T10 landed; evidence per task below). Parent spec:
`docs/aegis/specs/2026-11-19-probe-truth-and-ingest-boundary-design.md` (v2, decisions
grilled 2026-11-19). Rule: `docs/aegis/adr/0018-deprecation-grounds.md`.

This plan is being created for the multi-stage workstream the spec defines; it is not a
micro-plan for one slice.

## Goal

Make every stored probe outcome name its stage and cause, stop letting one ambiguous timeout
demote a link, give a second chance to the rows where the measurement — not the server — is
the likely failure, move a resolved name back into "not tested", and refuse at ingestion the
shapes no core can dial. Acceptance: the spec §10 (property gate + reported alive number).

## Architecture (owners)

| Concern | Owner |
| --- | --- |
| Ingest rules (`ss` method, `flow` requires TLS/REALITY, `flow=none` alias) | `leas-proto` (normaliser), `leas-config` (`validate_ss_config`, `validate_vless_shape`) |
| Outcome typing (`error_stage` × `error_cause`) | `leas-db` model + `schema/ddl.rs` v22 + `schema/steps.rs` + `SCHEMA_VERSION` |
| Probe policy (confirm, severity, in-flight, one stage-aware second dial, trace fallback) | `leas-native` (`ping_native`), `leas` (`ping` scheduler, `events` writer) |
| Name ⇒ not tested | `leas` (`enrich` resolve arm, `profiles::refresh_endpoint_ranks`) |
| Display `[dest]` | `leas` (`ui/profiles.rs`) |
| Capability (SOCKS5 gate, stale-marker refresh) | `leas-native` (`capability`), `leas` (`ping` pre-walk pass), `leas-oracles` |
| IP provider `cloudflare-trace` | `leas-config` (`IpProvider`), `leas-native` probe body parse |

## Tech stack

Rust 2024 workspace; toasty 0.11 + in-tree driver over turso 0.9.0-pre.5; `cargo nextest`;
`just quality-gate code` as the exit gate.

## Baseline / authority refs

`docs/reference/ordering-law.md` §2 bins, §6 resolution band + scopes ·
`docs/reference/database.md` schema cursor · ADR 0003 (ordering keys), 0006 (purge evidence),
0012 (migrations), 0017 (ingest validation precedent), 0018 (this rule) ·
report `docs/research/2026-11-19-real-test-funnel.md`.

## Compatibility boundary

- Schema 21 → 22 is a supported migration (ADR 0012 D-C): one `steps.rs` entry, rebuild, rows
  copied by explicit column list, both new columns nullable.
- No config-file migration: `probe_fallback_url` carries a serde default; `IpProvider` gains
  a variant with a stable string.
- No public API change. No CLI change. No export-schema change beyond the two new nullable
  columns (export/readback must round-trip them).

## TDD Route

`mode: auto` → **decision: strict for T1, T2, T3, T5 (behaviour/contract/persistence/migration);
light for T4, T6, T7, T8, T10 (single-owner, obvious focused check); skipped for T9 (dev-only
harness).** Authority: `AGENTS.md` test rules + this spec's §6. Verification per task, then
`just quality-gate code`.

## Change Necessity

| Task | Why no-change is insufficient | Minimum boundary |
| --- | --- | --- |
| T1 | 143 stored links and every future import carry a shape no codec can dial; prose cannot separate "invalid" from "broken server" | two validators + one parser normalisation |
| T2 | Reports are regex over prose; `error_kind` is frozen and cannot carry a stage | two nullable embed fields + one migration |
| T3 | 52.7 % timeouts are unconfirmed; one failure demotes a link | probe loop + ring call site |
| T4 | 102 endpoints resolve but stay marked `[name]` | one resolve hook + rank refresh |
| T5 | the 143 rows keep consuming budget | one marker-gated DATA step |
| T6 | exit IP missing on 4/14 successes | provider/parse completion |
| T7 | typed data with no visible payoff | one token in one cell |
| T8 | 51 links parked behind an untested gate | one oracle row + one-line flip |
| T9 | yield claims have no external check | dev-only harness |
| T10 | 490 markers describe an older build | one pre-walk pass |

## Tasks

### T1 — Ingest rules (S5, minus the DATA step) — **done, green**

Status: landed. `leas-proto` owns `NATIVE_SS_METHODS` + `native_supports_ss_method`;
`validate_ss_config` refuses an unrosterable method; `validate_vless_shape` refuses a
`flow` without TLS/REALITY; `flow=none` normalises to absent at parse; `leas-native` pins its
resolver to the roster. Verified: `cargo nextest run -p leas-proto -p leas-config` → 688/688,
plus the codec pin test.

Files: `crates/leas-proto/src/proto_spec/ss_method_support.rs`,
`crates/leas-proto/src/proto_spec/vless.rs`,
`crates/leas-config/src/import_export.rs`, `crates/leas-native/src/protocol/ss/method.rs`.

1. `leas-proto`: add `NATIVE_SS_METHODS` (names only) + `native_supports_ss_method`, trimmed and
   case-insensitive; a test pins the list is non-empty and rejects `null`/`telegram-id-x`.
2. `leas-native` `method.rs`: a test asserts `SsMethod::from_method` accepts exactly
   `NATIVE_SS_METHODS` and rejects `null`/`""`/garbage.
3. `validate_ss_config`: an unresolved method is `ImportError::Validation` naming it.
4. VLESS parse: `flow` equal to `none` (any case) becomes absent.
5. `validate_vless_shape` in `import_export.rs`: non-empty `flow` requires `security` `tls` or
   `reality`; error names the flow and the missing layer. Called beside `validate_ss_config`.

Verify: `cargo nextest run -p leas-config -p leas-proto`; rstest tables for both rules.

### T2 — Outcome typing (S1) — **landed for the batch path; one path pending**

Landed and verified:

- `FailureStage` / `FailureCause` model enums; `ErrorInfo` gains the pair as `error_stage` /
  `error_cause`. **Naming correction:** toasty prefixes embed fields itself and ignores
  `#[column]` inside an embed, so the spec's `failure_*` spelling was impossible without a
  raw-table hack; `error_*` sits beside `error_kind`/`error_text` and the spec/plan were
  updated.
- Schema 22: `V22_STAGE_CAUSE` derived from the v21 rebuild, the pair placed after
  `error_text` (the embed's order), a pair CHECK, both indexes recreated; `steps.rs` entry 22
  and `SCHEMA_VERSION` 22.
- Page projection, export readback, `failure_pair()` (class + `transport_failed` + evidence,
  no prose) with a 16-case rstest, the batch writer path through `apply_test_result`, and a
  persistence/clear test.
- Evidence (2026-11-19): `-p leas-proto -p leas-config` 688/688 · `-p leas-db` 262/262
  (incl. the v20→22 chain and the three `migration_v22` tests) · `-p leas -p leas-native`
  1344/1344 · `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features
  -- -D warnings` clean · `cargo fmt` clean. The four suites together are the default-member
  coverage; `leas-oracles` is excluded by design.

Pending, deliberately left as the next slice: the **single-ping event path** (`CoreEvent::SpeedTestResult`)
still passes `None`, so a row probed from the menu has a typed marker and a NULL pair. The
batch — where the corpus is measured — is typed. T3..T10 are untouched.

Files: `models_toasty.rs` (`ErrorInfo` gains `stage`/`cause` as optional enums with `Field`
impls, `#[column("failure_stage")]`/`#[column("failure_cause")]`), `schema/ddl.rs` (v22 rebuild
copying v21's list plus the two columns and a pair CHECK), `schema/steps.rs` (step 22),
`database.rs` (`SCHEMA_VERSION` 22), `profiles_query.rs` (projection + decode),
`events.rs` (`apply_test_result` writes the pair; success clears it), `ping_native.rs`
(`ProbeFailure` carries `(stage, cause)`).

Verify: migration fixture (v21 file → 22, NULL pair, `error_kind` unchanged); rstest
(ProbeClass × call site) → pair; pair CHECK rejects cause-without-stage.

### T3 — Probe policy (S2 + S3) — **landed**

Landed: `probe_attempts` is sequential (one confirm observation, `retries` as its
budget); the second observation's target is chosen by the first failure's stage (target →
fallback, dial → same); the persisted failure is the more informative by a severity ladder;
`ProbeOutcome::Failed` carries `confirmed` and the ring samples ONLY a confirmed failure
(success always samples; the fast-phase retirement no longer samples at all); the fallback
is `https://www.cloudflare.com/cdn-cgi/trace`, parsed for `ip=`/`loc=` so a fallback success
needs no second tunnel; `IpProvider::CloudflareTrace` is in the curated list. Tests: pair
table, severity/positive-evidence table, trace parser table, ring-gate test, sampling tests.

Read of the ground (2026-11-19), so the slice starts from facts:

- `SpeedTestConfig` (`leas-config/src/app_config.rs:473`) already carries `ping_url` with a
  `#[serde(default)]`; the fallback URL is one more field with a default — no config migration.
- `IpProvider` (`leas-config/src/ip_provider.rs:43`) is the curated list: `url()`,
  `is_family_forced()`, `fallback_chain()` and `parse(body)` are the four seams. A
  `CloudflareTrace` variant needs (a) the url `https://www.cloudflare.com/cdn-cgi/trace`,
  (b) a `parse` arm for the text body (`ip=`/`loc=` lines, not JSON), and (c) its name in
  `SELECT_CELL` — a test pins that every variant is offered there.
- The probe's attempt loop is `probe_attempts` (`ping_native.rs`): one `JoinSet`, `best` and
  `last_error` from completion order. T3 replaces it with a sequential loop and a
  severity-ordered `best_failure`; the second observation's target is chosen by the first
  failure's stage.
- The ring write is `sample_stability` called from `ping.rs` `after_fast_settle`/result paths;
  the gate ("confirmed") belongs at those call sites, not inside the sampling helper.


Files: `ping_native.rs` (`probe_attempts`: sequential attempts, severity-ordered failure,
GET + bounded body for the fallback, trace parse), `ping.rs` (stage-aware second observation;
`sample_stability` gated on agreement), `leas-config` (`probe_fallback_url`,
`IpProvider::CloudflareTrace`).

Verify: severity table; "single timeout ⇒ no ring sample"; "two agreeing ⇒ one sample";
trace parser table; in-flight property test.

### T4 — Resolved name ⇒ bin 12 (S4) — **landed**

Files: `enrich.rs` (the `Ok(ips)` arm emits `CoreEvent::NamesResolved`),
`events.rs` (handler: `Database::clear_name_markers` + `refresh_endpoint_ranks`),
`database.rs` (`clear_name_markers`, registered raw SQL). Test:
`clearing_name_markers_leaves_real_markers_and_purges_alone`.

Verify: DB test — name marker cleared, real marker kept, `rank_bin = 12`, purged stays 16.

### T5 — Stored invalid rows (S5 DATA step) — **landed**

Files: `database.rs` `purge_invalid_shapes_once` (marker-gated, called from `open`, uses
`proto_spec::is_undialable_shape` — the SAME predicate the ingest gate calls),
`proto_spec::is_undialable_shape`. Test: `invalid_shapes_are_retired_once`.

Verify: fixture with 3 shapes → 3 verdicts, second open no-op, ranks refreshed.

### T6 — Exit-IP coverage (S6) — **landed**

Files: `database.rs` `distinct_exit_ips` (registered raw SQL), `AggregateCounts::exit_ips`,
`state::refresh_aggregates`, `ui/details.rs` (`exit IPs`). Test:
`distinct_exit_ips_counts_servers_not_links`.

### T7 — `[dest]` (S7) — **landed**

Files: `ui/profiles.rs` (`RealCellFacts.dest`, computed from `latency_auth = ok` +
`error_stage = target`; `test_cell_content` branch). Test:
`test_cell_shows_dest_only_for_a_target_stage_failure_after_an_ok_ack`.

### T8 — SOCKS5 (S8) — **landed**

Files: `crates/leas-oracles/tests/socks5_client_oracle.rs` (sing-box SOCKS5 server + native
client, `#[ignore]`d), `capability.rs` (`kind_supported` admits `Socks`; the refusal list
test updated).

### T9 — Calibration harness (S9) — **landed**

`scripts/probe-calibration.py`: samples N links per (`error_stage`, `error_cause`) from a DB,
rebuilds each link's xray-core outbound, dials the probe target through it and prints the
agreement matrix (plus `--json`). Dev tooling, not a test; its first run belongs in a research
note.

### T10 — Stale-marker refresh (S10) — **landed**

Files: `ping.rs` `after_fast_settle`: the config-aware `capability::support_reason` runs for
every visited link (the protocol config is memoized per `ProtocolId`), so a refused row gets
the CURRENT reason even when its fast dial fails — the 490 stale markers can no longer outlive a batch.

## Verification

`cargo nextest run` per touched crate; `just quality-gate code` at the end; the property gate
from spec §10 on the live DB after a run.

## Risks and retirement

- Schema rebuild (T2) — schema-21 pattern, one transaction, fixture test.
- Probe wall time (T3) — one extra observation per failing link; no further increase.
- T8 unlocks untested code — the oracle row lands in the same change.
- Retirement: the old single-attempt fan-out and `last_error` are deleted in T3, not kept
  behind a flag; the untestable-prefix path stays (it is the CHECK-frozen marker).
