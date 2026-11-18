# Credential purge (`cred`) from the auth ack — implementation plan

Date: `2026-11-18`
Status: `executed 2026-11-18 (T1–T10; gate 3/3, real-core probe rows 4/4)`
Spec: `specs/2026-09-17-purge-reason-design.md` (amended 2026-11-18, D8–D11)
Source: grilling session of 2026-11-18 (decisions: strict evidence set, one-meaning `Failed`, fp veto kept, CHECK widened)

## Goal

A real probe whose AUTH evidence is credential-grade moves the link to Purgatory with the
`cred` label. Nothing weaker moves it. `AuthAck::Failed` becomes the single meaning
"credential-grade evidence", so column and verdict cannot disagree.

Non-goals: Hysteria2's broken stage-2 probe path, pooled/mux carriers (no AUTH consumer),
speed-test failures (existing policy: no verdict), older builds reading a newer export.

## Approved scope

| Decision | Value |
| --- | --- |
| `cred` evidence set | AnyTLS close/fallback before the first session frame, or `cmdAlert`; Hysteria2 non-233 at the h3 auth. Nothing else |
| VLESS | EOF / version / framing peels no longer set `Failed`; they stay `Unknown`. Wrong UUID never purges |
| VMess / SS2022 | response-header peel sets `Ok` only; they never purge |
| Evidence coupling | `Failed` ⇒ credential-grade ⇒ purge trigger; a probe that failed after `Ok` never purges (`Ok` is terminal) |
| Fingerprint veto | unchanged: an approximated `security_fp` earns no verdict, `cred` included |
| Storage | new `PurgeReason::CredentialRejected`; the `profile_stats` CHECK stays enforced and is widened by a table rebuild |

## Baseline / authority refs

- `docs/aegis/specs/2026-09-17-purge-reason-design.md` §6 (typed evidence), §7 (taxonomy), amendment of 2026-09-22 (fp veto).
- `docs/reference/database.md` (schema cursor 20 → 21, `purge_reason` enum).
- `AGENTS.md`: schema cursor rule (`schema::steps` + `SCHEMA_VERSION`), DB manual-SQL rule, test-shape rule.
- `crates/leas-native/src/error.rs` (`NativeError`, `FailureEvidence`), `protocol/mod.rs` (`AuthAck`, `AuthAckSlot`, `initial_auth_ack`).
- `crates/leas/src/ops/purge.rs` (the sole policy owner), `ops/ping_native.rs` (probe result assembly).
- `crates/leas-db/src/schema/{steps,ddl}.rs`, `models_toasty.rs` (`PurgeReason`, `ProfileStats`), `database.rs::purge_reason_str`, `export.rs`.

## Architecture and owners

- Evidence is typed where the failure happens: `NativeError::evidence()`. A new
  `FailureEvidence::CredentialsRejected` is the only engine-side addition; the Hysteria2 auth
  status maps to it through a new typed error.
- The ack slot stays the observation channel. `Ok` is terminal (new invariant); `Failed` is
  written only by the two credential predicates.
- The probe converts `auth_ack == Failed` on a FAILED attempt into the typed evidence; the purge
  policy stays one function, `purge::reason_for(evidence, fp)`.
- Persistence: one new `PurgeReason` variant; `profile_stats` is rebuilt once to widen the CHECK.
- UI: `purge_label` gains `cred`.

## Compatibility boundary

- DB: cursor 20 → 21, a migration step (no wipe). Rows, PK values and the two secondary indexes
  survive. A v21 file is unreadable by a v20 build (CHECK + cursor); that is the existing
  migration contract.
- Export: the string vocabulary gains `credential_rejected`; older builds reject a newer export
  (existing behaviour for an unknown reason string).
- AUTH column: VLESS rows that used to read `Failed` on a malformed/truncated peel now read
  `Unknown`; the `[real]` error text still names the cause.
- Purging: AnyTLS/Hysteria2 rows can now enter Purgatory on a real probe. Reversal stays the
  manual real retest.

## Change Necessity

`code-change`: the purge taxonomy is code (`reason_for`) plus a typed DB value; no config or doc
change can add a verdict, and no existing evidence variant expresses "the secret was rejected".

## TDD Route

`TDD Route: mode off, decision skipped.` Authority: repository convention (`AGENTS.md`) — no
explicit TDD request and no `~/.config/aegis/config.toml`. Posture: focused unit tests per task
plus the `#[ignore]`d real-core rows; no RED/GREEN pairing.

## Requirement ready check

Approved source: the 2026-11-18 grilling (options A, A, A, A). Scope, scenarios, acceptance and
the failure taxonomy are settled; no decision-changing unknown remains.

## Tasks

### T1 — typed credential evidence

Files: `crates/leas-native/src/error.rs`.

- Add `FailureEvidence::CredentialsRejected`.
- Add `NativeError::AuthRejected { detail: String }` with `#[error("authentication rejected: {detail}")]`;
  `evidence()` maps it to the new variant.
- Extend `evidence_is_the_single_owner_of_what_a_failure_proves` with the new arm (the test is
  exhaustive by construction).
- The enum is matched exhaustively outside the crate; the compiler finds the two that need an
  arm, and the plan names them so the choice is deliberate:
  `ProbeFailure::from_engine` (`crates/leas/src/ops/ping_native.rs:134`) → `ProbeClass::Protocol`
  (the proxy's own auth answer), and `inbound::reply_for`
  (`crates/leas-native/src/inbound/mod.rs:1533`) → `socks5::ReplyCode::GeneralFailure`.
  `is_transport_failure` has a `_ => false` wildcard and already answers correctly; pin it with a
  test rather than add an arm (see below).
- Test in `ping_native`: `from_engine(&AuthRejected{..})` yields `class == Protocol`,
  `evidence == Some(CredentialsRejected)`, `transport_failed == false` — the last one is what
  keeps a wrong-password row `[real]` instead of `[fast]`.

Proof: `cargo nextest run -p leas-native error`.

### T2 — VLESS stops claiming rejection

Files: `crates/leas-native/src/protocol/vless/stream.rs`, doc comments in
`crates/leas-native/src/protocol/mod.rs` (`AuthAck::Failed`) and
`crates/leas-db/src/models_toasty.rs` (`AuthState::Failed`).

- Delete `PeelAck` and the `ack: PeelAck` field (its only reader was the slot write); keep
  `ack_slot`.
- Remove the four `ack_slot.set(Failed)` writes (truncated version, non-zero version, truncated
  addons, and the first EOF arm); keep the errors and the `Ok` writes.
- Update `the_peel_reports_the_ack_into_its_slot`: the EOF and wrong-version cases assert
  `Unknown`; the accepted case still asserts `Ok`.
- Reword the `AuthAck::Failed`/`AuthState::Failed` docs to "credential-grade evidence".

Proof: `cargo nextest run -p leas-native vless`.

### T3 — AnyTLS credential predicate

Files: `crates/leas-native/src/protocol/anytls/session.rs`, `crates/leas-native/src/protocol/mod.rs`.

- `read_loop`: count frames; on every exit path, when `frames == 0` and the slot is not `Ok`,
  set `Failed` BEFORE `break`/`shutdown` (ordering: the probe's read error is triggered by
  `shutdown`, so the slot is written first). Keep `CMD_ALERT => Failed`.
- `AuthAckSlot::set`: ignore a write when the current value is `Ok` (terminal), with a unit test;
  a v2 session that errors after `cmdServerSettings` must not downgrade.

Pooling interaction, stated so the two plans cannot collide: the **probe never uses the session
pool** — `probe::fetch` → `dial_transport` → `finish_chain` → `protocol::connect` →
`anytls::connect` → `Session::start(…, ctx.ack)`, so every probe owns a fresh session and its own
slot. `anytls::client::connect_pooled` (the inbound path, `client.rs:47`) bakes the creating
context's slot into a session that later legs reuse; that slot has no AUTH consumer. The
mux-carrier-reuse plan pools MUX.COOL/sbox carriers, not this session pool. If a future caller
routes a *probe* through a pooled session, the slot must become per-leg (or the session must
publish into a shared cell read by each leg) before that caller can feed the AUTH column.

Proof: `cargo nextest run -p leas-native anytls`.

### T4 — VMess reports `Ok`

Files: `crates/leas-native/src/protocol/vmess/mod.rs`, `protocol/vmess/stream.rs`.

- Thread `ctx.ack.clone()` through `handshake` → `VmessClientStream::new` / `new_legacy` →
  `VmessRead::new` / `new_legacy` / `with_mode` (new field `ack_slot`).
- Set `Ok` after the legacy echo/option checks and after the AEAD echo check (the two points
  where the header is accepted). EOF, echo mismatch and framing stay `Unknown`.
- Extend the existing header round-trip tests with slot assertions (both wires).

Proof: `cargo nextest run -p leas-native vmess`.

### T5 — SS2022 reports `Ok`

Files: `crates/leas-native/src/protocol/ss/stream2022.rs`, `protocol/ss/mux.rs`.

- `Ss2022Stream::new` gains `ack_slot`; `connect` passes `ctx.ack.clone()`; `connect_to` gains a
  slot parameter (the mux path passes `AuthAckSlot::default()` — no AUTH consumer, documented).
- Set `Ok` in `decode_step` after `open_response_header` succeeds; every validation failure
  stays `Unknown`.

Proof: `cargo nextest run -p leas-native stream2022`.

### T6 — Hysteria2 typed rejection

Files: `crates/leas-native/src/protocol/hysteria2/quic.rs`.

- The `status != 233` arm returns `NativeError::AuthRejected { detail: format!("authentication
  failed, status code: {status}") }` instead of `Protocol { kind: Hysteria2, ... }`.
- Leave the per-request `TCPResponse` status check alone (not authentication).

Proof: `cargo nextest run -p leas-native hysteria2` plus T10's real-core row.

### T7 — probe → policy

Files: `crates/leas/src/ops/ping_native.rs`, `crates/leas/src/ops/purge.rs`.

- Wherever a failed attempt's `ProbeFailure` receives its `auth_ack`, set
  `evidence = Some(FailureEvidence::CredentialsRejected)` when the ack is `Failed` (a failed
  attempt only; a non-2xx target answer is not a `Failed` ack).
- `reason_for`: `FailureEvidence::CredentialsRejected => Some(PurgeReason::CredentialRejected)`;
  the fp-approximation veto stays above the match and covers it.
- Extend `every_typed_evidence_maps_to_its_reason` and the approximated test.

Proof: `cargo nextest run -p leas purge` and `cargo nextest run -p leas ping_native`.

### T8 — persistence and migration

Files: `crates/leas-db/src/models_toasty.rs`, `database.rs`, `export.rs`, `schema/ddl.rs`,
`schema/steps.rs`, `crates/leas/src/ui/profiles.rs`.

- `PurgeReason::CredentialRejected` + `purge_reason_str` → `"credential_rejected"`.
- Capture the live table DDL and its index names from a fresh DB
  (`SELECT sql FROM sqlite_master WHERE name LIKE 'profile_stats%'` via the
  `fresh_open_creates_tables_and_raw_ddl` path) and write `V21_CREDENTIAL_PURGE`:
  `CREATE TABLE profile_stats_v21 (...)` with the 8-value `purge_reason` CHECK and the unchanged
  `error_kind` CHECK; `INSERT ... SELECT` the full column list; `DROP TABLE profile_stats`;
  `ALTER TABLE profile_stats_v21 RENAME TO profile_stats`; recreate the two indexes.
- Add the step (`version: 21`), bump `SCHEMA_VERSION` to 21.
- Export both directions + round-trip test; `purge_label` → `"cred"`.
- New test in `tests/schema_migrate.rs`: build a **v20 fixture** (the same DDL with the 7-value
  CHECK, seeded rows, `PRAGMA user_version = 20`), open it, assert rows and PK survive, the two
  indexes exist, `credential_rejected` inserts and an unknown string is still refused, and the
  rebuilt table's `pragma_table_info` + CHECK match a freshly pushed v21 table.
- `docs/reference/database.md`: enum list, cursor 20 → 21.

Proof: `cargo nextest run -p leas-db` and `cargo nextest run -p leas-db --test schema_migrate`.

### T9 — spec, docs, index

Files: `docs/aegis/specs/2026-09-17-purge-reason-design.md`,
`docs/aegis/INDEX.md`.

- Append the 2026-11-18 amendment (D8–D11, the new evidence class, the v21 step, the demotion of
  VLESS's `Failed`). No new spec owner.
- Register this plan in the index.

### T10 — acceptance

- Hermetic: T1–T8 proofs above; plus a policy test that `Failed` + `security_fp = "qq"` earns no
  verdict.
- Real-core (`#[ignore]`, `LEAS_CORE_BIN_DIR`): extend `crates/leas-oracles/tests/probe_e2e.rs`:
  - AnyTLS, wrong password → `auth_ack == Failed` (the `[cred]` evidence is derived
    above this layer, by `credential_evidence`);
  - AnyTLS, right password, refused target → `auth_ack == Ok`: the v2
    `cmdServerSettings` frame precedes the target request, so the secret is accepted
    even though the target failed (no `[cred]` possible);
  - Hysteria2, wrong password → `NativeError::AuthRejected`;
  - sing-box VLESS, wrong UUID → `Unknown` — the target-failure discriminator, because
    sing-box writes its response header lazily.
- Gate: `just quality-gate code` (fmt + clippy + the suite).

## Verification

```text
cargo nextest run -p leas-native error
cargo nextest run -p leas-native vless
cargo nextest run -p leas-native anytls
cargo nextest run -p leas-native vmess
cargo nextest run -p leas-native stream2022
cargo nextest run -p leas-native hysteria2
cargo nextest run -p leas purge
cargo nextest run -p leas-db
cargo nextest run -p leas-oracles --test probe_e2e --run-ignored   # needs the pinned cores
just quality-gate code
```

## Risks

- The v21 step hand-writes `profile_stats` DDL; the fresh-vs-migrated shape test is the guard.
- Hysteria2 non-233 also fires for a non-hysteria endpoint → a wrong-port row purges as `cred`.
- AnyTLS zero-frame close can be a restart or a middlebox reset → false `cred` on a rare path.
- A `Failed` written after `Ok` would purge a healthy config; the terminal-`Ok` guard in the slot
  is the defence and must land with T3.

## Retirement

- `PeelAck` (VLESS) — deleted.
- The untagged `Protocol { kind: Hysteria2 }` auth message — replaced by `AuthRejected`.
- The "framing error ⇒ Failed" wording in the `AuthAck`/`AuthState` docs — replaced.

## Execution route

`inline`: T1 → T2/T3/T4/T5/T6 → T7 → T8 → T9/T10. The engine tasks share the evidence type;
T8 is independent of T2–T6 but needs T1. User confirmation required: no.
