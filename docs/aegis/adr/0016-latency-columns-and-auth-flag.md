# ADR 0016 — The latency row carries two delays and an auth flag; the discriminator is dropped

Date: 2026-10-21
Status: **accepted — DESIGN APPROVED, IMPLEMENTATION PENDING** (slice 1 of
`specs/2026-10-21-merged-test-pipeline-design.md`)
Amends: ADR 0012 (decision 3 — the migration cursor now has a real step list),
ADR 0011 (the column-retirement discipline)
Related: ADR 0015 (the merged test pipeline), ADR 0003 (the stored ordering
keys), `docs/reference/ordering-law.md`, ADR 0006 (the purge evidence)

## Context

`profile_stats` carried one measurement per row, in a toasty **enum** embed:

```rust
pub enum Latency {
    Real { #[shared(delay)] delay: i32, ip: Option<String> },
    Fast { #[shared(delay)] delay: i32 },
}
```

`#[shared(delay)]` puts both variants' delay in ONE column (`latency_delay`),
and the enum's **discriminator** (`latency` = `'real'` / `'fast'` / `''`)
selects which variant owns it. The row can therefore hold a real delay **or**
a fast delay, never both — the exclusivity is structural, not a convention.

ADR 0015's merged probe produces **both** numbers in one pass: the transport
span (stage 1) and the real span (stage 3). A row that carries one of them
cannot carry the other, so the embed has to change.

The change also had to fit a codebase with **no migration machinery at all**:
`crates/leas-db/src/schema/mod.rs:155-160` reads *"There are none yet"* — a
cursor between 0 and 18 is reported as `IncompatibleSchema`, which
`Database::open` answers with a **wipe**. ADR 0012 D-C already decided the
policy ("a supported older version applies the pending steps; only an UNKNOWN
cursor wipes"), but no step list existed to carry it.

## Decision

1. **The `Latency` embed becomes a struct**, and the discriminator is
   **dropped**:

   ```
   profile_stats.latency             DROPPED
   profile_stats.latency_real_delay  RENAMED from latency_delay
   profile_stats.latency_fast_delay  NEW
   profile_stats.latency_ip          kept
   profile_stats.latency_auth        NEW
   ```

   A toasty **struct** embed flattens into prefixed columns
   (`toasty-macros-0.11.0/src/lib.rs:848-870`), so
   `latency: Latency { real_delay, fast_delay, ip, auth }` produces exactly
   those four columns and no discriminator. The enum's discriminator was what
   made the two delays mutually exclusive; removing the enum removes the
   exclusivity.

2. **The schema change is migration 19, and the cursor grows a step list.**
   ADR 0012 D-C's policy is implemented for the first time: the cursor holds
   the newest APPLIED version, a supported older version applies the pending
   steps in order, and only an unknown cursor wipes. The step list lives next
   to the DDL (`crates/leas-db/src/schema/`), and the cursor advances **in the
   same transaction** that applies the step.

   ```
   ALTER TABLE profile_stats RENAME COLUMN latency_delay TO latency_real_delay;
   ALTER TABLE profile_stats ADD COLUMN latency_fast_delay INTEGER;
   ALTER TABLE profile_stats ADD COLUMN latency_auth INTEGER;
   UPDATE profile_stats SET latency_fast_delay = latency_real_delay WHERE latency = 'fast';
   ALTER TABLE profile_stats DROP COLUMN latency;
   PRAGMA user_version = 19;
   ```

   The data step runs **before** the discriminator is dropped, so a `'fast'`
   row's number is not lost.

3. **The step list is NOT folded into `ensure_raw_ddl`.** That function
   re-runs *idempotent* `ADD COLUMN`s on **every** open and tolerates exactly
   one error string ("duplicate column", `schema/ddl.rs:92-94`).
   `RENAME COLUMN` and `DROP COLUMN` are **not** idempotent — they fail with
   "no such column" on a second application. They are safe **only because the
   cursor gates them**: a step is applied when `cursor < 19`, and the cursor
   becomes 19 in the same transaction. A database at 19 never re-runs them.

4. **No CHECK list is added.** `latency_auth` is a plain integer
   (`NULL` = never observed; 1 = ok, 2 = failed, 3 = n-a, 4 = unknown), and the
   `error_kind` and `purge_reason` CHECK lists are untouched. So the
   `profile_stats` table is **not** rebuilt.

   **The mechanism is load-bearing.** A toasty **enum** embed emits `TEXT`
   with a `CHECK (col IN (...))` on SQLite/Turso
   (`toasty-core-0.11.0/src/schema/db/ty_enum.rs:5`), and a column's CHECK
   cannot be altered afterwards (SQLite forbids changing one; a new variant
   means a table rebuild). A toasty **struct** embed flattens its fields into
   plain columns with no CHECK. So the auth states are a **Rust-side enum**
   in `leas-db` (one `as_i64` / `from_i64` pair) behind a plain
   `Option<i64>` field — the `stab_mask` / `stab_len` precedent, already two
   plain integers. A toasty enum embed for the auth states would put a CHECK
   on the column, and the first state added later would cost a
   `profile_stats` rebuild.

5. **The ordering law re-derives without changing its bands.** "Is this a
   real or a fast measurement?" becomes "**is `latency_real_delay` non-null?**".
   A row can now carry both; the real one wins the band, exactly as the old
   exclusivity guaranteed ("a real measurement outranks a fast one of any
   delay"). The band count and every band's meaning are unchanged.

6. **The Auth flag does not enter the band law.** It is a status, not a
   measurement, and no band has room for a third axis. It is a TUI fact (a
   column between Fast and Real) and a purge input only if ADR 0006's
   amendment changes.

## Why

- **The exclusivity was the defect.** The merged probe measures two things;
  the schema could hold one. A struct embed is the smallest shape that holds
  both, and it *removes* a column instead of adding a second spelling of one
  fact.
- **Dropping the discriminator is cheaper than keeping it.** Keeping `latency`
  as a discriminator would mean a fourth value ("both"), a CHECK-list change
  and a rule for which variant's other fields survive — for a column whose
  only remaining reader is the "is it real or fast?" question, which the
  non-null test answers.
- **The migration must be a migration.** ADR 0012 D-C decided the policy; the
  cursor's "apply the pending steps" arm was the one piece never built. A
  column rename + two column adds + a discriminator drop is the first change
  in this project's history that needs it, and building it here is what makes
  the next one routine.
- **A table rebuild is a cost to avoid.** The `PurgeReason` and `error_kind`
  CHECK lists are frozen (ADR 0006 decision 2: *"one nullable TEXT column and
  one CHECK list"*; ADR 0004 alternative 3 for the marker kinds). A new
  CHECKed value would force a rebuild of `profile_stats` — the largest table
  in the schema. The auth flag's integer encoding sidesteps that entirely.

## Alternatives considered

1. **`ADD latency_real_delay` + `UPDATE` + keep `latency_delay`.** Rejected: a
   vestigial second spelling of one fact, read by nobody and paid for by
   every write.
2. **Keep the enum, add a third variant `Both`.** Rejected: the enum's
   discriminator + a `Both` variant means the column's value no longer says
   which delay is where, and `latency_ip` would have to be re-decided for the
   new variant.
3. **A separate `latency_fast` table.** Rejected: a second owner for a
   measurement that belongs to the link, and a join on every page read.
4. **The auth flag as a boolean (`auth_ok`).** Rejected: the flag has four
   states, and `n-a` must be distinguishable from `unknown` — a boolean
   collapses them, and `unknown` is the state the design exists to
   distinguish.
5. **`Step::Rebuild` for the reshape.** Rejected: the data migrates (a copy
   into the new column), so an in-place step suffices. `Rebuild` is reserved
   for identity re-keys (ADR 0012 D-C).
6. **Store the auth flag in `error_text`.** Rejected: `error_text` is swept by
   the error-TTL policy, and the flag is a durable status, not a transient
   error message.

## Consequences

- **A version-18 database migrates in place**; a foreign version still wipes
  (ADR 0012's rule, unchanged).
- **26 raw-SQL sites across 6 files** that name `latency_delay` are
  re-pointed: `database.rs` (the upsert), `merge.rs`, `export.rs`,
  `profiles_query.rs` (the page projection + decoder), `endpoint_rank.rs`
  (the rank refresh), and the raw-SQL test fixtures.
- The **stability seed** changes shape: it selects `WHERE latency = 'real'`
  today (`schema/mod.rs:193-199`) and must select
  `WHERE latency_real_delay IS NOT NULL` — and the day-one stamp's meaning
  must be re-derived, because the seed's own key (`latency = 'real'`) is a
  column that no longer exists.
- The **rank refresh** reads `real_delay.or(fast_delay)` where it read
  `match link.latency`.
- The **export/import** round trip carries four measurement columns instead of
  two plus a discriminator.
- The `Latency` type's shape changes — it is a crate-internal model, so no
  public API outside `leas-db`'s existing `pub fn`s is affected.

## Documentation obligation (slice 1)

This ADR changes the schema, so the reference set must be updated **in the
same slice** — `docs/reference/database.md` (the `profile_stats` mermaid
block), `docs/reference/glossary.md` (the `Latency` entry) and
`docs/reference/database-manual-sql.md` (the raw-SQL table, including the
stability seed's `WHERE latency='real'` predicate). A pending marker in one
doc and silence in the others would leave the set describing two schemas at
once.

`docs/reference/ordering-law.md` is **not** touched in slice 1: the band law
does not move until slice 3, and the reference doc describes shipped
architecture. It is a slice-3 task (ADR 0015's slice 3).

## Verification (planned, slice 1)

- A version-18 database opens, migrates, and reads back with the **same
  numbers**: a `'real'` row keeps its delay in `latency_real_delay`; a
  `'fast'` row's delay is in `latency_fast_delay`.
- A version-19 database opens unchanged, and reopening it **does not** re-run
  the RENAME or the DROP (the non-idempotency trap).
- A foreign cursor still reports `IncompatibleSchema` and takes the wipe.
- The stability seed still marks exactly the rows with a real measurement.
- The page projection, the merge and the export round trip carry the four
  columns.

## Boundary

This ADR records an **approved design**, not a shipped implementation. It
moves to SHIPPED when slice 1 of
`specs/2026-10-21-merged-test-pipeline-design.md` lands. This record grants no
completion authority.
