# sqlx instead of toasty? Decision memo (2026-11-27)

Question: replace `toasty` (and our 734-line Turso driver fork) with **sqlx** plus a
Turso backend, exposing typed models as plain `FromRow` structs, with DDL and
migrations in SQL? A reference adapter (`avencera/sqlx-turso`) was cloned to
`thirdparty/sqlx-turso` and port-probed against our engine.

**Verdict: do not migrate now.** The sqlx side of the swap is a 6 899-line
alpha backend that pins turso `0.7.0-pre.3` (two cycles behind our
`0.9.0-pre.5`) and has not been touched since 2026-05-28; the typing win it would
buy is achievable with a few hundred lines we already half-own. The premise that
toasty is unmaintained is also wrong on the evidence: 45 commits since the 0.11.0
release, the last on 2026-11-23. The one real friction is release cadence (no
0.12 tag yet), and that does not justify a backend rewrite.

## 1. The premise, checked

| Claim | Evidence |
| --- | --- |
| "toasty is not actively maintained" | **Refuted.** `tokio-rs/toasty` has 45 commits since `toasty-v0.11.0` (2026-09-24), last commit 2026-11-23 (compare API). Release cadence: 0.9.0 2026-07-23, 0.10.0 2026-08-11, 0.11.0 2026-09-24 — roughly every six weeks. What is true: **no 0.12 release yet**, so a fix lands only via a git pin until the next tag. |
| "sqlx is a drop-in, we just need an adapter" | sqlx itself is healthy (0.9.0 2026-05-21, 0.9.1 2026-11-18). The Turso adapter is **not** stock sqlx: it is `0.1.0-alpha.1`, last commit 2026-05-28, 7 849 lines, and its checked-query macros are its own (`sqlx_turso::query!` + a `sqlx-turso prepare` CLI), not `sqlx::query!`. |

## 2. What we actually have today

Measured on this tree (`wc -l`, greps before each file's `#[cfg(test)]`):

| Piece | Size | Notes |
| --- | ---: | --- |
| `models_toasty.rs` (14 models + 1 test-only probe) | 1 724 lines | derive-based models, embeds, enums, newtype ids, `Deferred` relations |
| `database.rs` | 6 786 lines (3 194 non-test) | 28 typed query call sites and 11 raw `toasty::sql::query` in the non-test part; the 154-site count includes tests |
| `write_behind.rs` / `endpoint_rank.rs` / `endpoint_ip.rs` / `profiles_query.rs` | 2 348 / 2 315 / 612 / 1 374 | mostly raw SQL by design; four raw sites in `write_behind`, 11 in `endpoint_rank` |
| `driver/mod.rs` (vendored fork) | 734 lines | nine `toasty_core::driver` trait impls; bounded by design, no statement cache growth (it routes around `prepare_cached` because our bulk writers inline literals) |
| schema layer | `ddl.rs` 268, `steps.rs` 222, `rekey.rs` 916 | `user_version` cursor; SQL steps plus a `Rebuild` kind for data re-keys |
| transactions | 9 non-test sites | MVCC mode issues `BEGIN CONCURRENT` from the driver's default-begin hook |

So the hot paths are already hand-written SQL; the ORM's job in this crate is
typed single-table reads/writes and the schema/DDL/migration convenience, not
query composition at scale.

## 3. The sqlx-turso reference, measured

Cloned to `thirdparty/sqlx-turso` (shallow, 50 commits) and copied to `/tmp` for a
port probe; the copy was discarded after the run.

| Fact | Value |
| --- | --- |
| Version / last commit | `0.1.0-alpha.1`, last commit **2026-05-28** (six months before this audit) |
| Size | 7 849 lines: core 6 899, macros+CLI 568, facade the rest |
| sqlx pin | `sqlx = "=0.9.0"` (stable line; 0.9.1 exists) |
| turso pin | `turso = "=0.7.0-pre.3"` — our crate pins `0.9.0-pre.5` |
| Port to turso 0.9.0-pre.5 | **One compile error**: `error[E0004]: non-exhaustive patterns: &turso::Error::BatchStatementFailed { .. } and &turso::Error::BatchRollbackFailed { .. } not covered` — a two-arm match fix; nothing else moved |
| Statement cache | bounded, `options.get_statement_cache_capacity()` — this removes the exact unbounded-cache motive that made us own a driver |
| Transactions | savepoints by depth; `BEGIN CONCURRENT` exercised in its own tests (MVCC works) |
| Migrations | SQLx migration traits + `_sqlx_migrations`; SQL files only |
| Checked queries | custom macro family + `sqlx-turso prepare` writing `.sqlx/*.json`; bind arity checking impossible (turso exposes no parameter metadata) |
| Stated gaps | read-only opens rejected, immutable opens rejected, autovacuum unsupported, stored generated columns unsupported, remote sync untested |

**What this means.** The engine-level part of a sqlx backend is a solved problem
for turso 0.9 — the adapter compiles with one match arm added. The durability of
the *dependency* is the issue: an alpha crate, six months stale, pinned two
engine versions back, with its own macro/CLI stack that only it maintains.

## 4. Option comparison

| Criterion | A. Stay on toasty (today) | B. sqlx + sqlx-turso | C. Drop the ORM, thin Turso layer + plain structs |
| --- | --- | --- | --- |
| Typed row structs | derive `Model` (generates query builders, updates, relations) | `#[derive(FromRow)]` — plain structs | plain structs + ~30-line decode impls (we already have `driver/value.rs::from_turso_infer`) |
| Query construction | typed builders for 28 reads / 15 writes | hand SQL, runtime-decoded, or custom macros with metadata | hand SQL (already the norm for the hot paths) |
| Statement cache | none by design (inlined literals; our fork routes around `prepare_cached`) | bounded by option | ours to write (~50 lines) |
| Pool | deadpool via toasty (`2 × cpu`) | sqlx pool (configurable) | `deadpool` directly or a small semaphore (`leas-db` already depends on `deadpool` transitively only through toasty; it would become direct) |
| Migrations | `user_version` + SQL steps + Rust `Rebuild` kind | `_sqlx_migrations` + SQL files; the Rust data steps stay imperative | unchanged (keep ours) |
| Compile-time checked SQL | no | only via the adapter's own macros + `.sqlx` metadata + a custom CLI in CI | no |
| Code we own | 734 lines of driver | 0 lines today, but a 7.8k-line alpha dependency we would fork on first break | ~300–500 lines (mostly existing decode/param code) |
| Engine coupling | our pin (turso 0.9.0-pre.5) | adapter pins 0.7.0-pre.3 → port on every engine bump | our pin, one crate |
| MVCC `BEGIN CONCURRENT` | driver default-begin hook | adapter has `begin_with`, default begin is ANSI `BEGIN` (callers must opt in) | explicit, as today |
| Breaking-change exposure | one ORM release per ~6 weeks (0.10→0.11 had 5 breaking changes; all absorbed) | sqlx semver + alpha adapter semver + adapter's own course | none third-party |

The decisive asymmetry: **B replaces a 734-line integration we control with a
7.8k-line alpha integration we do not**, and the part that would actually shrink
our codebase (typed reads/writes) is 32 call sites in non-test code (28 reads,
4 writes), not 154.

## 5. What we would gain and lose

Gains specific to sqlx, in order of realness:

1. `FromRow`/`Type` derives on **plain structs** — the user's stated goal
   ("typed model outside `leas-db`"). Real, but option C gives the same with a
   struct + an impl, and the adapter's `Type` impls for newtypes/enums/JSON
   would be ours to write anyway. The shape is small either way:

   ```rust
   #[derive(Debug, Clone)]
   pub struct ProtocolRow {
       pub id: i64,
       pub sig: i64,
       pub config: String,   // deferred JSON column, decoded by the caller
   }
   // sqlx:  impl<'r> FromRow<'r, TursoRow> for ProtocolRow { ... }
   // option C: impl Decode for ProtocolRow { fn decode(row: &TursoRow) -> ... {} }
   ```

   What the derive-based layer adds on top of that shape is the query builder
   and partial-update machinery — the part costing 1 724 lines of model
   definitions and 32 non-test call sites.
2. A maintained pool and savepoints. We already have both (deadpool underneath
   toasty; savepoint depth is in the adapter, not in our code).
3. SQL migration files. Our `StepKind::Sql` is already shaped like that; the
   `Rebuild` (identity re-key, 916 lines in `rekey.rs`) is Rust and stays Rust
   under any migration system. Converting `user_version` to `_sqlx_migrations`
   adds a cursor-migration step and a second source of truth during the change.
4. Compile-time checked SQL — the one capability we do not have, and the one
   that costs a `.sqlx/` artifact commit, a `sqlx-turso prepare` step in CI, and
   a custom macro namespace. Our build currently needs no database at compile
   time; this would change that.

Losses: toasty's partial-update builders (4 non-test write sites), its relation loading
(used at least by the merge path's link handling), and the `Json`/embed column
mapping that the derive does for the 1 724-line model file.

## 6. Recommendation

1. **Do not adopt sqlx now.** The risk is the **adapter**, not sqlx: sqlx 0.9.1
   is current (2026-11-18), while `sqlx-turso` is `0.1.0-alpha.1`, six months
   stale, and pins an engine two releases behind ours. It is not a drop-in for
   `sqlx-sqlite`: adopting it means owning the 6 899-line core (7 849 with the
   macro/CLI stack) on every turso bump, or forking it when upstream stops.

   **Port price, measured as far as a compile goes:** one non-exhaustive `match`
   over `turso::Error` (two arms) to build the core against `0.9.0-pre.5`. What
   that does *not* prove: its own test suite on 0.9, runtime type mapping,
   `RETURNING`, savepoint nesting, and the checked-query `.sqlx` metadata flow.
   Price it as a spike, not a migration.

   **Go/no-go for option B** (all four must hold):
   - the ported core passes its own test suite against `0.9.0-pre.5`, not just
     `cargo check`;
   - our perf-lab (`import_wal_vs_mvcc`, `plan_sweep`, `reader_contention`) is
     byte-identical or better on the ported adapter — SQL and plans, not just
     tests;
   - `BEGIN CONCURRENT`/MVCC and the bounded statement cache are exercised by a
     test we can point at, and the adapter has a release newer than
     `0.1.0-alpha.1` or an upstream commitment (issue/PR) to track turso;
   - the fork surface we would own is bounded: if the port needs edits outside
     `options.rs`/`error mapping`, that is a no-go regardless of test results.

2. **If ORM friction becomes the problem** (0.12 still unreleased when the next
   schema change lands, or a second breaking bump in a row), run **option C as a
   bounded spike**: a `query/exec/params/rows` layer on turso (reusing
   `driver/value.rs` and the raw readers), plain structs replacing the 14 models,
   and the 28 non-test typed reads + 4 typed writes converted. Kill criteria:
   if the spike exceeds ~1 000 lines of new code or cannot keep
   `tests/turso09_lab.rs` plans byte-identical, stop and stay on toasty.
   Implementation detail, API-level evidence and the phased plan are in §9.
3. **Keep the schema layer either way.** `user_version`, the SQL steps, and the
   Rust re-key step are orthogonal to the ORM choice; sqlx's migration table buys
   nothing that our cursor does not already do.
4. **Borrow from `sqlx-turso` regardless of the choice**: its URL-query option
   parsing (`options.rs`), its bounded statement cache pattern, its savepoint
   depth handling (`transaction.rs`), and its type-mapping table
   (`value.rs`/`column.rs`) are compact, tested references for any future
   adapter work.
5. **The real pivot point is the engine, not the ORM.** If storage ever moves to
   a sqlx-supported engine (stock SQLite via `sqlx-sqlite`, 10 642 maintained
   lines, no backend to own), sqlx becomes the cheap option. Against turso, a
   sqlx backend is always a crate we have to keep alive.

## 7. What would change this verdict

- `sqlx-turso` publishes a 0.2 that tracks turso ≥ 0.9 and sqlx ≥ 0.9 with
  `BEGIN CONCURRENT` and statement-cache tests in CI.
- toasty misses a second release cycle while our schema work is blocked on it.
- The app drops the MVCC mode (removing the `BEGIN CONCURRENT` requirement) —
  that widens the acceptable backends but does not change the maintenance math.
- A measured win from `FromRow` typing that option C cannot reach.

## 8. Limits of this evidence

- The port probe is `cargo check -p sqlx-turso-core` against turso
  `0.9.0-pre.5` in a `/tmp` copy; no sqlx-turso test suite was run, and its
  runtime behaviour (type mapping, `RETURNING`, savepoints) against 0.9 is
  unverified beyond compile.
- The 7 849-line figure is the adapter as cloned on 2026-11-27 (50-commit
  shallow history); on crates.io it is published only as `0.1.0-alpha.1`, and
  no newer release was looked for beyond that.
- "Gains" for option B are capability statements from its README and source, not
  benchmarks; no performance comparison was run, because the two stacks do not
  coexist in this workspace (the adapter requires turso 0.7, a second engine copy
  is possible but the driver APIs differ).
- toasty cadence is commit counts from the GitHub compare/commits API; release
  dates from its changelogs.
- `thirdparty/sqlx-turso` is an unmanaged reference clone (not in
  `thirdparty.toml`); `refresh.py` will report it until `python3 refresh.py
  --sync` is run.

## 9. Option C concretely: Turso directly (no sqlx, no toasty)

**It works, and a probe verified the exact shapes this crate needs.** A
throwaway binary (`/tmp`, `turso = "=0.9.0-pre.5"`, no other database crate)
did, and printed:

```
cross-conn: name="x" blob_len=2
returning: id=2 name="y"
prepared count: 2
after mvcc tx count: 3
```

i.e. two connections on one file `Database` see each other's committed rows;
`INSERT … RETURNING` decodes through `Statement::query_row`; a prepared
statement is reused with a bound parameter; and `PRAGMA journal_mode='mvcc'`
plus `transaction_with_behavior(TransactionBehavior::Concurrent)` commits and is
visible on the other connection.

### The API we would rely on (read from the pinned crate)

| Need | Turso 0.9.0-pre.5 API | Where |
| --- | --- | --- |
| open file / memory | `Builder::new_local(path).build().await`, `Database::connect()` | `src/lib.rs:381` |
| execute / query | `Connection::{execute, query, prepare}`, `Statement::{execute, query, query_row}` | `src/connection.rs:354`, probe |
| row decode | `Rows::next`, `Row::get::<T>(idx)`, `column_name(s)` | `src/rows.rs:47,108` |
| transactions | `Connection::transaction_with_behavior`, `set_transaction_behavior` (per-connection default) | `src/transaction.rs:285,353` |
| MVCC begin | `TransactionBehavior::Concurrent` → `BEGIN CONCURRENT` | `src/transaction.rs:9-35` |
| one-transaction batch | `Connection::transactional_batch` | `src/connection.rs:221` |
| statement cache | `prepare_cached` — an **unbounded** `HashMap<String, …>` | `turso_sdk_kit/src/rsapi.rs:1144` |
| pool | **absent** from the binding | — |

Note `transaction*` methods take `&mut Connection`; a pooled design therefore
hands out an owned connection per checkout, which is what our 9 transaction
sites already assume.

### What already runs without toasty

Six files import `turso` directly today: the direct reader connection
(`database.rs::open_direct_conn`), the whole page projection
(`profiles_query.rs`), the export reader (`export.rs`), the error classifier
(`driver/error.rs`), value encode/decode (`driver/value.rs`), and the driver
itself. The display path is already raw SQL; the typed path exists mostly as the
parity oracle (`load_page_rows`/`load_endpoint_rows`) and typed CRUD.

### What we would write, sized against this tree

| Piece | Today | Under raw Turso |
| --- | --- | --- |
| driver/`toasty` trait impls | `driver/mod.rs` 734 lines (9 trait methods) | ~150-line `Conn` helper: open + pragmas + per-connection begin behavior |
| statements | toasty executes | `prepare`/`execute`/`query`; keep the inline-literal bulk writers; add a bounded LRU (~50 lines) only if a hot repeated statement is measured |
| pool | deadpool under toasty (`2 × cpu`) | `deadpool` directly, ~60 lines (it is currently only a transitive dep) |
| typed rows | derive `Model`, 1 724 lines incl. tests | plain structs + reuse of `driver/value.rs::from_turso_infer` (105 lines) |
| table DDL | generated by `push_schema` from the models | 14 `CREATE TABLE` statements (~250–300 lines) move into `schema/ddl.rs`; the cursor, steps and `ensure_raw_ddl` are unchanged |
| relation loads (oracle path) | toasty `Deferred` loads in `load_endpoint_rows` | ~100 lines of SQL, mirroring the raw projection it is the oracle for |
| untyped conversions | 179 non-test `toasty::` references outside models/driver, of which 28 typed reads + 4 typed writes are real work | mechanical |

Net: delete roughly 1.5–2.4k lines of toasty-specific code, add roughly
0.6–0.9k. That is less owned code than sqlx-turso's 6 899-line core, and every
line is about our schema.

### Phased plan (each phase keeps the app green)

1. **Schema first.** Write the 14 `CREATE TABLE`s in `schema/ddl.rs` and skip
   `push_schema` when the cursor is current. Gate: `in_memory_db_has_full_schema_and_roundtrips`,
   the migration tests, and the table-shape assertions. This phase is useful even
   if the rest never happens: it makes DDL explicit and removes the drift risk
   from a codegen change.
2. **Reads.** Port the 28 typed reads to `prepare`/`query` with the plain
   structs. Gate: `tests/profiles_query.rs` parity and the leas-db suite.
3. **Writes and transactions.** Port the 4 typed writes and 9 transaction sites
   to `transaction_with_behavior` (keeping `BEGIN CONCURRENT` when the MVCC flag
   is on). Gate: `import_wal_vs_mvcc`, `single_row_wal_vs_mvcc`,
   `reader_contention_wal_vs_mvcc`.
4. **Delete.** Drop `toasty`, `toasty-core`, `toasty-sql`, the 734-line driver
   and the derive on the models. Gate: workspace clippy, `cargo nextest run`,
   plan sweep byte-identical.

Kill criteria (same as the spike): more than ~1 000 new lines, or any of the
perf-lab plans/ratios move without an explanation.

### Risks specific to this option

- Turso is `0.9.0-pre.5`: its builder/statement API can change under us. We
  already ride that through the driver; direct use just moves the churn closer.
- The schema becomes hand-written. The guard is tests: the schema-shape test,
  the migration tests, and one `PRAGMA table_info` assertion per table.
- The typed page oracle loses an independent implementation. Replace it with
  golden rows captured before the port, or keep the projection test as the
  single-source truth.
- Hand-written SQL for writes: no builder catches a renamed column; the
  integration suite is the only net.
