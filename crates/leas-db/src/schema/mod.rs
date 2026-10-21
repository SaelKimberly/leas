//! The schema's single owner: a versioned migration cursor.
//!
//! Replaces the previous `PRAGMA user_version` tag, whose ONLY behaviours were
//! "run `push_schema`" and "otherwise DELETE the database file" (AGENTS
//! decision 4). A tag mismatch was therefore a wipe, never a migration; there
//! was no way to add a column, an index, or a table to an existing feed.
//!
//! See `docs/aegis/specs/2026-10-08-db-adapter-and-migrations-design.md` §5 and
//! §5.1, and `ddl.rs` for where every hand-written statement lives.
//!
//! # The cursor
//!
//! `PRAGMA user_version` holds the newest APPLIED migration version. The list
//! SEEDS at the schema the crate ships today (`SCHEMA_VERSION`, 18), so on the
//! day this lands an existing tag-18 file is already current and a fresh file
//! applies 18 — no data is touched either way. Every later change is 19+.
//!
//! # What a mismatch means now
//!
//! * `cursor == latest` — the schema is current. Ensure the raw DDL exists
//!   (idempotent) and return.
//! * `cursor == 0` — a fresh file. Create the tables, then the raw DDL.
//! * `0 < cursor < latest` — apply the migrations after `cursor`, in order.
//! * anything else — a foreign or pre-migration file. That is NOT a migration
//!   opportunity: those schemas are unreadable by this code, so it is reported
//!   as `Incompatible` and the caller applies its documented wipe. This is an
//!   EXPLICIT verdict; previously the same situation was inferred from a
//!   `CREATE TABLE` failing.

use toasty_core::driver::operation::TransactionMode;

use crate::Result;
use crate::error::DatabaseError;
use crate::models_toasty::AppMeta;

pub mod ddl;
pub mod steps;

/// The version this crate's schema is at. Distinct from
/// [`crate::database::SCHEMA_VERSION`] only in that this one is the cursor's
/// authority; they must agree, and a test pins it.
pub const LATEST: i64 = crate::database::SCHEMA_VERSION;

/// Read the migration cursor. Reuses the crate's one PRAGMA decoder so the
/// cursor and every other `PRAGMA` read cannot drift.
async fn cursor(conn: &mut impl toasty::Executor) -> Result<i64> {
    let rows = toasty::sql::query("PRAGMA user_version").exec(conn).await?;
    Ok(crate::database::first_i64(&rows).unwrap_or(0))
}

/// Apply the raw DDL: the (non-idempotent) column adds first, then the
/// idempotent indexes and tables.
///
/// The ALTERs are attempted every time and their duplicate-column error is
/// TOLERATED — this engine has no `ALTER ... IF NOT EXISTS`, and the error is
/// the only signal that the column is already there. Any OTHER error is real
/// and propagates.
///
/// The stability seed's own one-way stamp: its presence means the day-one seed
/// has run on this database. `app_meta` is the typed key/value table the PSL
/// version already uses.
///
/// **v2** (schema 19): the seed's predicate used to name the `latency`
/// discriminator column, which migration 19 DROPS. A v1-stamped database has
/// already been seeded, so its rings are populated and it must not re-seed —
/// but it must also not be read as "never seeded" and re-seeded with the new
/// predicate. The distinct key says "the seed ran" without naming a column
/// that no longer exists.
const STABILITY_SEEDED_KEY: &str = "stability_seeded_v2";

async fn ensure_raw_ddl(conn: &mut impl toasty::Executor) -> Result<()> {
    for alter in ddl::STAB_ADD_COLUMNS {
        if let Err(e) = toasty::sql::query(*alter).exec(conn).await {
            let message = e.to_string();
            if !message.contains("duplicate column") {
                return Err(e.into());
            }
        }
    }
    for alter in ddl::ENDPOINT_RANK_ADD_COLUMNS {
        if let Err(e) = toasty::sql::query(*alter).exec(conn).await {
            let message = e.to_string();
            if !message.contains("duplicate column") {
                return Err(e.into());
            }
        }
    }
    for statement in ddl::V18_AFTER_ALTERS {
        toasty::sql::query(*statement).exec(conn).await?;
    }
    Ok(())
}

/// Bring `db`/`conn` to the current schema version.
///
/// `db` is needed only to create the TABLES: a toasty model's `CREATE TABLE`
/// comes from `push_schema`, which is the schema of record until the typed
/// layer is retired (see `ddl.rs`). Everything toasty cannot express comes from
/// [`ddl`].
pub async fn migrate(db: &toasty::Db, conn: &mut toasty::Connection) -> Result<()> {
    match cursor(conn).await? {
        v if v == LATEST => {
            // Current. Still ensure the derived tables/indexes exist — this is
            // the only path a database created before a new raw statement was
            // added to `ddl.rs` takes, and every statement is idempotent.
            ensure_raw_ddl(conn).await?;
            // Day-one stability seed (spec `2026-10-09-stab-bin-design` §6.2).
            // `latency_real_delay IS NOT NULL` is evidence a real success
            // happened — `apply_test_result` writes the real delay only on
            // success and KEEPS it when it later writes an error — but an
            // existing database's rings are empty, so every
            // previously-successful link
            // would read `rank_proven = 0` and drop out of ALL four scoped
            // menus. Seeding the ring with that one known success keeps
            // `proven` true and the window neutral (one sample < `STAB_WARMUP`).
            //
            // Keyed on a DURABLE STAMP, never on "did the ALTER just run":
            // a kill between the ALTER and this UPDATE would otherwise leave
            // every pre-upgrade success with an empty ring, and every later
            // open would see "duplicate column", skip the seed, and strand
            // those endpoints outside all four scopes until each was re-probed
            // (weeks on a large feed). The stamp is written in the same
            // transaction as the seed, so the pair is all-or-nothing.
            seed_stability_once(conn).await?;
            Ok(())
        }
        0 => {
            // Cursor 0 with existing foreign tables: `push_schema` emits
            // `CREATE TABLE` without `IF NOT EXISTS`, so it FAILS on a table it
            // did not create. That failure IS the incompatibility signal — an
            // untagged, foreign or half-created file — and it is reported
            // explicitly so the caller applies its documented wipe. (The old
            // code inferred the same thing from the same failure; here it is a
            // named verdict.)
            db.push_schema().await.map_err(|e| {
                let message = e.to_string();
                if message.contains("already exists") {
                    DatabaseError::IncompatibleSchema(0)
                } else {
                    DatabaseError::Toasty(e)
                }
            })?;
            ensure_raw_ddl(conn).await?;
            // Stamp the seed as done: a freshly created database has no links,
            // so there is nothing to backfill, and the stamp keeps the
            // invariant "every database that has completed an open is stamped"
            // true on this path too (the backfill is a MIGRATION concern; a
            // link that earns its real latency later gets its ring from the
            // probe that measured it).
            toasty::sql::query(format!(
                "INSERT INTO app_meta (key, value) VALUES ('{STABILITY_SEEDED_KEY}', '{}') \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                i64::from(crate::endpoint_rank::STAB_VERSION)
            ))
            .exec(conn)
            .await?;
            toasty::sql::query(format!("PRAGMA user_version = {LATEST}"))
                .exec(conn)
                .await?;
            Ok(())
        }
        other => {
            // 0 < other < LATEST: apply the steps after `other`, in order.
            // ADR 0012 D-C's policy, implemented for the first time (the
            // step list is `schema::steps`).
            //
            // A cursor below the FIRST step's version names the pre-alpha tag
            // world, where 1..17 were unrelated schemas: neither readable nor
            // migratable. That is reported as incompatible, and `open` applies
            // its documented wipe.
            if other >= 1 {
                let steps = steps::steps_after(other);
                if let Some(steps) = steps {
                    apply_steps(conn, steps).await?;
                    return Ok(());
                }
            }
            Err(DatabaseError::IncompatibleSchema(other))
        }
    }
}

/// Apply the migration steps, in order, and advance the cursor to the
/// version they produce.
///
/// The steps and the cursor advance in **ONE transaction**: a kill between
/// them cannot leave a half-migrated file (the steps applied, the cursor not
/// advanced — which would re-run the non-idempotent RENAME/DROP and fail).
/// The cursor stamp is what makes the steps safe to apply at all.
async fn apply_steps(conn: &mut toasty::Connection, steps: &[steps::Step]) -> Result<()> {
    let mut tx = conn
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let result = async {
        // The cursor advances to the LAST step's version — the steps are
        // applied in order, so the last one is the newest schema.
        let mut version = 0;
        for step in steps {
            match step.kind {
                steps::StepKind::Sql(statements) => {
                    for statement in statements {
                        toasty::sql::query(*statement).exec(&mut tx).await?;
                    }
                }
                steps::StepKind::Rebuild => {
                    return Err(DatabaseError::Generic(
                        "migration step `Rebuild` is not implemented yet".into(),
                    ));
                }
            }
            version = step.version;
        }
        toasty::sql::query(format!("PRAGMA user_version = {version}"))
            .exec(&mut tx)
            .await?;
        Ok::<(), DatabaseError>(())
    }
    .await;
    match result {
        Ok(()) => {
            tx.commit().await?;
            tracing::info!(target: "leas_db",
                "profile_stats: applied the latency reshape (schema 19)");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The day-one stability seed: give every link that has a real measurement a
/// one-sample success ring, so `rank_proven` is true for it immediately.
///
/// `latency_real_delay IS NOT NULL` is the "a real measurement happened"
/// predicate — the same one the rank refresh reads now that the `latency`
/// discriminator is gone (schema 19). Only a REAL measurement seeds: a fast
/// latency is a transport handshake, which proves nothing about the config.
///
/// Runs at most ONCE per database, and the seed and its stamp land in ONE
/// transaction — so the crash window the ALTER-gated form had (ALTER applied,
/// seed lost, every later open skipping it) cannot exist. A first open with
/// nothing to seed still stamps, because "there were no real links yet" is a
/// settled answer: a link that earns a real latency later gets its ring from the
/// probe that measured it, never from this backfill.
async fn seed_stability_once(conn: &mut toasty::Connection) -> Result<()> {
    let already: Option<String> = AppMeta::filter_by_key(STABILITY_SEEDED_KEY.to_owned())
        .first()
        .exec(&mut *conn)
        .await?
        .map(|m| m.value);
    if already.is_some() {
        return Ok(());
    }
    let mut tx = conn
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let result = async {
        let count = scalar_count(
            &mut tx,
            "SELECT COUNT(*) FROM profile_stats WHERE latency_real_delay IS NOT NULL",
        )
        .await?;
        toasty::sql::query(
            "UPDATE profile_stats SET stab_mask = 1, stab_len = 1 \
             WHERE latency_real_delay IS NOT NULL",
        )
        .exec(&mut tx)
        .await?;
        // CLEAR the key-input stamp so `endpoint_rank::ensure` (later in
        // `open`) sees a mismatch and recomputes every stored key: the seeded
        // rings must reach `rank_proven`/`rank_stab` or the seed does nothing
        // visible. `rank_weight_meta` may not exist on a very old file; the
        // rank `ensure` creates it, so a failed delete is not an error.
        let _ = toasty::sql::query("DELETE FROM rank_weight_meta")
            .exec(&mut tx)
            .await;
        toasty::sql::query(format!(
            "INSERT INTO app_meta (key, value) VALUES ('{STABILITY_SEEDED_KEY}', '{}') \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            i64::from(crate::endpoint_rank::STAB_VERSION)
        ))
        .exec(&mut tx)
        .await?;
        Ok::<i64, DatabaseError>(count)
    }
    .await;
    match result {
        Ok(count) => {
            tx.commit().await?;
            tracing::info!(target: "leas_db",
                "profile_stats: seeded {count} proven links into the stability ring");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// One integer from a single-value query (the schema module's own copy; the
/// rank module's is private to `endpoint_rank`).
async fn scalar_count(conn: &mut impl toasty::Executor, sql: &str) -> Result<i64> {
    let rows = toasty::sql::query(sql).exec(conn).await?;
    Ok(rows
        .first()
        .and_then(|row| match row {
            toasty_core::stmt::Value::Record(record) => record.fields.first().cloned(),
            _ => None,
        })
        .and_then(|v| match v {
            toasty_core::stmt::Value::I64(n) => Some(n),
            _ => None,
        })
        .unwrap_or(0))
}
