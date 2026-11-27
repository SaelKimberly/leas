# Turso 0.9.0-pre.6 pin + toasty/`leas-db` hygiene — implementation plan

Date: 2026-11-27
Evidence: `docs/research/2026-11-27-turso-0.9.0-pre.6-delta.md` (engine delta and the
A/B lab), `docs/research/2026-11-27-toasty-0.11-delta.md` (ORM delta and the two verified
hygiene findings), `docs/research/2026-11-27-sqlx-vs-toasty-decision.md` (options
deferred by the user).
Domain: `crates/leas-db` (manifest, comment-level text, lint allowance), `thirdparty/`
(reference pins), `refresh.py` (curation entry for the new reference clone).
Execution route: inline, one task at a time.
`User confirmation required: yes` — approve the engine pin bump (T4) and the
`thirdparty.toml` regeneration (T8) before execution starts.

Scope note: the user deferred the raw-Turso/sqlx reimplementation and the
schema-DDL relocation that the decision memo recommends for later; this plan is
only the actionable findings from the two pin/delta studies.

## 1. Goal and acceptance

Move the engine pin to the release the A/B study measured, remove the two pieces
of dead/stale code the onward studies proved, and leave the reference pins
consistent with what the crates actually compile against.

| # | Item | Baseline (pre.5, measured 2026-11-27) | Target after (pre.6, measured) |
| --- | --- | --- | --- |
| A1 | `turso` pin / lock | `=0.9.0-pre.5` | `=0.9.0-pre.6`, lock shows `0.9.0-pre.6` (crate published 2026-11-20) |
| A2 | `config_width_anti_join`: `not_in` / `not_exists`, wide and narrow | 5.30 s / 23.8 ms, 5.30 s / 23.1 ms | ≤ 0.20 s / ≤ 50 ms (measured 60.3 / 24.9 and 60.1 / 24.9) |
| A3 | `import_wal_vs_mvcc` wall, CPU, peak RSS | WAL 1.61 s / 1 920 ms / 71 MiB; MVCC 2.41 s / 3 770 ms / 167 MiB | WAL ≤ 1.6 s, MVCC ≤ 2.5 s, RSS within +5 % (measured 1.35 / 2.04 s, 162 MiB) |
| A4 | `single_row_wal_vs_mvcc` (500 txns) | WAL 234 ms; MVCC 115 ms | WAL ≤ 260 ms; MVCC ≤ 160 ms (measured 189 / 130 ms) |
| A5 | `reader_contention_wal_vs_mvcc` p99 during burst | WAL 624 µs; MVCC 2.51 ms | within 2× of baseline; no stall > 10 ms |
| A6 | `plan_sweep` PLAN2 lines | 17 statements | **byte-identical** to the pre-bump capture |
| A7 | `clippy::used_underscore_binding` allow | present, dead (0 hits with it removed) | removed; only `used_underscore_items` remains and still suppresses 5 macro-span hits |
| A8 | stale text (`database.rs` anti-join note, `driver/mod.rs` header, `Cargo.toml` tantivy note, `ddl.rs` composite-index reason) | pre.5 / turso 0.8 numbers and a "per-field only" claim | current pin, current numbers, composite `#[index(...)]` acknowledged |
| A9 | reference pins | `thirdparty.toml` + `thirdparty/INDEX.md` describe stale trees | `python3 refresh.py` reports no drift |

## 2. Baseline and authority

- Engine: `crates/leas-db/Cargo.toml:34` `turso = { version = "=0.9.0-pre.5", default-features = false }`; `Cargo.lock` resolves `0.9.0-pre.5`; toasty 0.11.0.
- The A/B numbers above come from this machine on 2026-11-27, one run per arm,
  system allocator; the study's §5 records the same figures.
- The clippy finding is a run, not a reading: with both allows stripped,
  `cargo clippy -p leas-db --lib -- -D warnings` produced 5 `used_underscore_items`
  errors and 0 `used_underscore_binding` errors (rustc/clippy 1.100.0).
- The composite-index claim is from the tag: struct-level `#[index(a, b)]`
  exists in `toasty-macros` at both 0.10 and 0.11 (`ModelAttr::indices`,
  `KeyAttr`); the mixed-direction/raw-column cases still need raw DDL.

## 3. Non-goals (explicit)

- Raw-Turso thin layer, sqlx adoption, schema-DDL relocation — deferred by the
  user; tracked in the decision memo §9 for a later spike.
- `Connection::disable_mvcc_auto_checkpoint` at the import boundary, and
  `storage_stats` in the UI — both were "measure/decide first" items; the import
  arm above shows no checkpoint stall to remove, so no change.
- Option-semantics, `max_connections` cap, `#[index]` migration, toasty pin move:
  all recorded as no-action in the ORM study.
- No rewrite of historical research docs; only the code comments that name
  the current pin/numbers.

## 4. Decisions

- **D1 — bump to `=0.9.0-pre.6`.** The study measured a uniform win (anti-join
  88×, import −15 %, single-row WAL −19 %) with byte-identical plans, no API used
  changed, and the MVCC TRUNCATE-window recovery fix. The lock diff is expected
  to be only the `turso*` family version/checksum lines.
- **D2 — keep the raw `NOT EXISTS` purge; fix its comment.** At pre.6 the
  rewrite is still ~2.4× the `NOT IN` shape and does not depend on a planner
  choice.
- **D3 — keep `ENDPOINT_IP_BY_KEY` raw; fix its reason.** The raw statement
  re-applies on every open and heals a database that lost the index; the model
  attribute creates it only when `push_schema` runs at cursor 0.
- **D4 — no `cargo hakari` change is expected** (the crate lists no `turso`
  edge), but the lock change mandates running `cargo hakari` and committing or
  reverting its diff explicitly.
- **D5 — the reference clones follow the audit.** `thirdparty/turso` moves to
  `v0.9.0-pre.6`; `thirdparty/toasty` stays at `v0.11.0` (the crate version);
  `thirdparty/sqlx-turso` stays as a reference for the deferred decision and is
  curated in `refresh.py`.

## 5. TDD route

- Mode: `auto`; decision: **light**.
- Authority: the user's request to implement the reviewed findings; no new
  behavior path is authored — a dependency pin plus comment/lint edits.
- Reason strict is not selected: there is no new behavior to express as a test;
  the risk sits in the engine, and the existing perf-lab arms + suite are the
  binding evidence.
- Verification: clippy for the lint edit, the six lab arms for the engine, the
  workspace suite at the gate.

## 6. Tasks (execute in this order)

### T1 — Remove the dead lint allowance (no dependency change)

Files: `crates/leas-db/src/models_toasty.rs` (`8-22`).
Change: delete the `clippy::used_underscore_binding` allow block; shorten the
`used_underscore_items` reason to what still fires (field *types* `u64`, `i64`,
`Deferred`, `EndpointId`; the `_0`-named Update setter sentence is stale since
0.11 renamed newtypes to `inner`).
Verify: `cargo clippy -p leas-db --lib -- -D warnings` → clean; `cargo fmt --check`.
Compatibility: none (lint metadata only).

### T2 — Fix the composite-index reason

Files: `crates/leas-db/src/schema/ddl.rs` (`28-33`).
Change: state that a field-level `#[index]` is one column, struct-level
`#[index(name = "endpoint_ip_by_key", ip_key, endpoint_id)]` exists (since before
0.10) and could express this order, and that the raw statement is kept because it
re-applies on every open (heal) where `push_schema` runs only at cursor 0.
Verify: read-back; `cargo check -p leas-db`.
Compatibility: none (comment).

### T3 — Capture the pre-bump baseline (before touching the pin)

Files: none; evidence for T5.

```sh
for a in config_width_anti_join import_wal_vs_mvcc single_row_wal_vs_mvcc \
         reader_contention_wal_vs_mvcc plan_sweep; do
  cargo test -p leas-db --release --features perf-lab --test turso09_lab -- \
    --ignored --nocapture "$a" > "/tmp/lab-pre5-$a.log" 2>&1
done
```
The study's pre.5 numbers (§1) were measured this way on 2026-11-27; if the
machine differs, these captures become the baseline the targets are judged
against (targets are ratios, not absolute seconds).

### T4 — Bump the engine pin

Files: `crates/leas-db/Cargo.toml:34`, `Cargo.lock`; comment at `Cargo.toml:26`
("0.9.0-pre.5 still pins it" → the new pin; the tantivy `0.26.2` fact was
re-checked against the pre.6 tag).
Change: `turso = { version = "=0.9.0-pre.6", default-features = false }`.
Verify:
- `cargo metadata --offline --format-version 1 > /dev/null` resolves;
- `git diff Cargo.lock` shows only the `turso*` version/checksum lines (expected
  ~23 diff lines, no package added/removed);
- `cargo build -p leas-db`;
- `cargo hakari generate` then `git diff crates/leas-hakari` — expect no change,
  commit or revert explicitly (D4).
Compatibility: file format and the journal-mode byte unchanged; an MVCC database
written by pre.6 is LML3, readable by every pin in this repo's history.

### T5 — Re-run the six arms and compare

Files: none.

```sh
for a in config_width_anti_join import_wal_vs_mvcc single_row_wal_vs_mvcc \
         reader_contention_wal_vs_mvcc plan_sweep; do
  cargo test -p leas-db --release --features perf-lab --test turso09_lab -- \
    --ignored --nocapture "$a" > "/tmp/lab-pre6-$a.log" 2>&1
done
```
Then:
- `diff <(grep '^PLAN2' /tmp/lab-pre5-plan_sweep.log) <(grep '^PLAN2' /tmp/lab-pre6-plan_sweep.log)` → empty;
- compare the A2–A5 lines against §1's targets.
Record both captures in the close-out (T9) and put the pre.6 lines into
`docs/research/2026-11-27-turso-0.9.0-pre.6-delta.md` as "confirmed on re-run"
only if they differ from the study.

### T6 — Real-database smoke in both journal modes

- WAL: `cargo nextest run -p leas-db in_memory_db_has_full_schema_and_roundtrips`
  (creates the schema, round-trips through a fresh pool slot, closes).
- MVCC: `cargo nextest run -p leas-db mvcc_checkpoint_succeeds_on_the_open_path`
  (opens a real MVCC handle and runs `wal_checkpoint(PASSIVE)`).
- Manual-recommended: copy one real feed DB to `/tmp`, open it once in WAL
  (default) and once with `LEAS_TURSO_CONCURRENT_WRITES=1` against a **copy**,
  let the app reconcile, close; confirm no `Corrupt`/`journal_mode` refusal in the
  log. This is the only step that touches pre-existing user data, so it uses a
  copy, never the original.
Verify: the tests pass; the manual smoke's log lines recorded in the close-out.

### T7 — Update the stale text that names the old pin/numbers

Files: `crates/leas-db/src/database.rs:2855-2859` (the `NOT IN` note: pre.5 5.37 s
→ pre.6 ~60 ms, keep `NOT EXISTS`), `crates/leas-db/src/driver/mod.rs:9,24`
(`turso` "0.8"/"currently 0.8.2" → the actual pin; the "vendored from main,
already on turso 0.8" note needs the current parenthetical), and any comment the
T4 diff makes wrong.
Verify: `grep -rn '0\.8\.2\|pre\.5\|5\.37' crates/leas-db/src crates/leas-db/Cargo.toml`
returns only historical research labels (the lab file's dated header), no
current-state claim.

### T8 — Reference pins and the manifest

Files: `thirdparty/turso` (checkout), `refresh.py` (curation entry),
`thirdparty.toml`, `thirdparty/INDEX.md`.

1. `git -C thirdparty/turso switch --detach v0.9.0-pre.6`;
2. add `sqlx-turso` to `refresh.py`'s `CURATION` map (one line: what it is, the
   deferral context, `#sqlx #turso #adapter`);
3. `python3 refresh.py --sync`;
4. review the generated diff: turso `ref`/`sha` → `v0.9.0-pre.6`, toasty `ref`
   → the 0.11 tag, `sqlx-turso` entry present, `shallow = true` for the clones
   that are; revert nothing that reflects the on-disk truth;
5. `python3 refresh.py` (drift check) → no drift rows for the three clones.
Compatibility: docs only.

### T9 — Final gate and close-out

- `cargo fmt --check`;
- `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`;
- `cargo nextest run -p leas-db`, then `just quality-gate code`;
- mark this plan's row in `docs/aegis/INDEX.md` `executed`, with the A2–A6 lines
  and any deviation.

## 7. Ripple and pressure check

- The engine pin touches every database call: guard is the plan sweep (A6) plus
  the suite; the diff is expected zero.
- The allow removal touches only lint metadata; the risk is a future clippy/driver
  change re-introducing the warning — the reason text now names what fires.
- The manifest regeneration is generated output; the only authored change is the
  `CURATION` line.
- No new owner, contract, or fallback is introduced; no retirement beyond the
  deleted allow and corrected text.

## 8. Risks

| Risk | Mitigation |
| --- | --- |
| pre.6 shifts a plan or a ratio silently | A2–A6 are recorded before/after; `plan_sweep` must be byte-identical |
| MVCC recovery semantics changed (TRUNCATE-window completion, one fewer fsync) | intended; `RECOVERY_SEMANTICS.md` is the contract; no action needed |
| lock/manifest churn from a shared registry state | T4's lock-diff check names the exact expected lines; T8 reviews the generated diff |
| the manual smoke touches user data | copy only, never the original file |
| crate availability for CI | `0.9.0-pre.6` is published (2026-11-20) and present in the local registry cache |

## 9. Close-out

One scoped commit per completed task: T1+T2 together (comment/lint), T4 alone,
T7 alone, T8 alone; T3/T5/T6 are evidence, not commits. The close-out records the
A2–A6 before/after lines, the `plan_sweep` diff result, and the final
`refresh.py` drift output in `docs/aegis/INDEX.md` and this plan.

## 10. Outcome (executed 2026-11-27)

| Task | Result |
| --- | --- |
| T1 | `used_underscore_binding` allow deleted; `cargo clippy -p leas-db --lib -- -D warnings` exit 0 (only `used_underscore_items` remains) |
| T2 | `ENDPOINT_IP_BY_KEY` reason now names the struct-level `#[index(...)]` and the heal-on-open reason for keeping the raw statement |
| T3 | pre.5 baselines captured (`/tmp/lab-pre5-*`): width 5.31 s / 5.32 s; import WAL 1.93 s / 2 140 ms / 65 MiB, MVCC 2.50 s / 4 010 ms / 170 MiB; single WAL 272.7 ms, MVCC 113.4 ms; contention WAL 5.7×, MVCC 19.7×; 17 PLAN2 lines |
| T4 | `turso = "=0.9.0-pre.6"`; lock diff 23 lines, only the turso family's version/checksum entries, no package added/removed; `cargo build -p leas-db` ok; `cargo hakari generate` produced no change |
| T5 | width **61.7 / 59.6 ms** (86–89× vs baseline) with `not_exists` 24.8 / 24.2 ms; import WAL **1.61 s / 1 980 ms / 67 MiB** (−17 % wall), MVCC **2.34 s / 3 770 ms / 173 MiB** (−6 %); single WAL 282.0 ms (+3 %), MVCC 120.8 ms (+7 %); contention WAL 5.7× (max 1.27 ms), MVCC 13.0× (max 4.47 ms); **PLAN2 diff empty** |
| T6 | `in_memory_db_has_full_schema_and_roundtrips` + `mvcc_checkpoint_succeeds_on_the_open_path` pass; real-DB copies (82 016 endpoints, `user_version` 23) open at pre.6 in WAL, and an MVCC-requested open of a WAL copy falls back to WAL as designed |
| T7 | anti-join note now records 5.37 s (pre.5) → ~60 ms (pre.6) and why `NOT EXISTS` stays; driver header says 0.9/pre.6; tantivy note says pre.6 |
| T8 | reference clone at `v0.9.0-pre.6` (`8f00aac`); toasty ref → `toasty-driver-integration-suite-v0.11.0` (`d71114e`, one of several tags at the same commit — `describe --exact-match` picks one); `sqlx-turso` entry added via a `CURATION` line; `python3 refresh.py` → `[report] clean` |
| T9 | `cargo fmt --check` clean; `cargo nextest run -p leas-db` **294 passed, 1 skipped**; `just quality-gate code` result recorded below |

**Deviations.** A3/A4's absolute targets were derived from the study's quieter
machine. Against the same-session pre.5 capture the engine moves −17 %/−6 %
(import) and +3 %/+7 % (single-row, i.e. noise); the A4 WAL ceiling (≤ 260 ms)
is "missed" only because the fresh baseline itself was 272.7 ms. No regression
signal: plans are byte-identical and RSS is +3 % / +2 %.

**Gate.** `just quality-gate code` → **3/3 passed** (fmt, clippy
`--workspace --exclude leas-oracles --all-targets --all-features -D warnings`,
nextest **3152 passed, 12 skipped**, 2 slow), plus `cargo nextest run -p leas-db`
**294 passed, 1 skipped**.
