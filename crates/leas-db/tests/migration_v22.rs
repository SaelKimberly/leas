//! The v22 stage × cause rebuild, executed against a v21-shaped table.
//!
//! These tests own the SQL artifact itself: `Database::open`'s wrapper (cursor,
//! pause between steps, rekey calls) is covered by every other database test,
//! and the step's registration is covered by `schema::steps`'s own tests. What
//! cannot be inferred from either is whether the rebuild preserves rows and
//! refuses a half pair — that is what runs here.

use leas_db::schema::ddl::{V21_CREDENTIAL_PURGE, V22_STAGE_CAUSE};

/// A v21 `profile_stats` under its final name: the v21 CREATE with the temporary
/// suffix removed.
fn v21_create() -> String {
    V21_CREDENTIAL_PURGE[0].replace("profile_stats_v21", "profile_stats")
}

const V21_ROW: &str = "INSERT INTO profile_stats \
    (protocol_id, endpoint_id, last_seen_at, error, error_kind, error_text, \
     stab_mask, stab_len, traffic_today_up, traffic_today_down, traffic_total_up, \
     traffic_total_down, created_at, updated_at, version) \
    VALUES (11, 22, 1700000000, 1, 'real', 'boom', 0, 0, 0, 0, 0, 0, 5, 6, 1)";

async fn v21_fixture() -> (tempfile::TempDir, turso::Database) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v21.db");
    let db = turso::Builder::new_local(path.to_str().expect("utf-8 path"))
        .build()
        .await
        .expect("local db");
    let conn = db.connect().expect("connection");
    conn.execute(&v21_create(), ()).await.expect("v21 table");
    conn.execute(V21_ROW, ()).await.expect("v21 row");
    (dir, db)
}

#[tokio::test]
async fn the_rebuild_preserves_the_row_and_leaves_the_pair_unknown() {
    let (_dir, db) = v21_fixture().await;
    let conn = db.connect().expect("connection");
    for statement in V22_STAGE_CAUSE {
        conn.execute(statement, ()).await.expect("v22 statement");
    }
    let mut rows = conn
        .query(
            "SELECT protocol_id, endpoint_id, error_kind, error_text, error_stage, error_cause \
             FROM profile_stats",
            (),
        )
        .await
        .expect("read migrated row");
    let row = rows.next().await.expect("query").expect("one row");
    assert_eq!(row.get::<i64>(0).expect("protocol_id"), 11);
    assert_eq!(row.get::<i64>(1).expect("endpoint_id"), 22);
    assert_eq!(row.get::<String>(2).expect("kind"), "real");
    assert_eq!(row.get::<String>(3).expect("text"), "boom");
    // Unknown is honest: the pre-22 rows were never classified, so both
    // columns are NULL rather than a guess derived from prose.
    assert!(row.get::<Option<String>>(4).expect("stage").is_none());
    assert!(row.get::<Option<String>>(5).expect("cause").is_none());
}

#[tokio::test]
async fn the_pair_check_refuses_a_cause_or_a_stage_alone() {
    let (_dir, db) = v21_fixture().await;
    let conn = db.connect().expect("connection");
    for statement in V22_STAGE_CAUSE {
        conn.execute(statement, ()).await.expect("v22 statement");
    }
    // Both together are legal.
    conn.execute(
        "UPDATE profile_stats SET error_stage = 'dial', error_cause = 'timeout'",
        (),
    )
    .await
    .expect("a full pair is legal");
    // Either alone is not.
    assert!(
        conn.execute("UPDATE profile_stats SET error_stage = NULL", ())
            .await
            .is_err(),
        "a cause without a stage must be refused"
    );
    assert!(
        conn.execute(
            "UPDATE profile_stats SET error_stage = NULL, error_cause = 'refused'",
            (),
        )
        .await
        .is_err(),
        "a cause without a stage must be refused"
    );
    assert!(
        conn.execute(
            "UPDATE profile_stats SET error_stage = 'target', error_cause = NULL",
            (),
        )
        .await
        .is_err(),
        "a stage without a cause must be refused"
    );
}

#[tokio::test]
async fn the_rebuild_keeps_both_indexes() {
    let (_dir, db) = v21_fixture().await;
    let conn = db.connect().expect("connection");
    for statement in V22_STAGE_CAUSE {
        conn.execute(statement, ()).await.expect("v22 statement");
    }
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
             AND name IN ('index_profile_stats_by_endpoint_id', \
                          'index_profile_stats_by_last_seen_at')",
            (),
        )
        .await
        .expect("index count");
    let row = rows.next().await.expect("query").expect("row");
    assert_eq!(row.get::<i64>(0).expect("count"), 2);
}

/// A FRESH database is created by `push_schema`, which cannot emit the rebuild's
/// table CHECK; `ensure_raw_ddl` installs the pair triggers instead, so the
/// invariant holds at the same `SCHEMA_VERSION` on both provenance paths.
#[tokio::test]
async fn a_fresh_database_enforces_the_pair_through_the_trigger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fresh.db");
    let db = leas_db::Database::open(&path).await.expect("fresh open");
    let mut conn = db.connection().await.expect("connection");
    toasty::sql::query(
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, \
         stab_mask, stab_len, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version) \
         VALUES (1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)",
    )
    .exec(&mut conn)
    .await
    .expect("seed link");
    assert!(
        toasty::sql::query("UPDATE profile_stats SET error_stage = 'dial'")
            .exec(&mut conn)
            .await
            .is_err(),
        "a half pair must be refused on a fresh file too"
    );
    toasty::sql::query("UPDATE profile_stats SET error_stage = 'dial', error_cause = 'timeout'")
        .exec(&mut conn)
        .await
        .expect("a full pair is legal");
}
