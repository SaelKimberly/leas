//! The v23 DNS step and its indexes, executed against a v22-shaped
//! `dns_settings` table.
//!
//! These own the SQL artifact: the step's registration is covered by
//! `schema::steps`'s tests, and the wrapper by every database test. What
//! cannot be inferred is whether the ALTERs land on an existing table and
//! whether the indexes are safe to apply on both provenance paths.

use leas_db::schema::ddl::{V23_DNS_ADD_COLUMNS, V23_DNS_INDEXES, V23_DNS_SOURCES};

async fn v22_fixture() -> (tempfile::TempDir, turso::Database) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v22.db");
    let db = turso::Builder::new_local(path.to_str().expect("utf-8 path"))
        .build()
        .await
        .expect("local db");
    let conn = db.connect().expect("connection");
    conn.execute(
        "CREATE TABLE dns_settings (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \
         \"servers\" TEXT NOT NULL, \"hosts\" TEXT NOT NULL, \"query_strategy\" TEXT, \
         \"disable_cache\" BOOLEAN NOT NULL, \"disable_fallback\" BOOLEAN NOT NULL, \
         \"client_ip\" TEXT, \"cache_ttl_secs\" BIGINT)",
        (),
    )
    .await
    .expect("v22 dns_settings");
    (dir, db)
}

#[tokio::test]
async fn the_step_adds_three_tables_and_two_columns() {
    let (_dir, db) = v22_fixture().await;
    let conn = db.connect().expect("connection");
    for statement in V23_DNS_SOURCES {
        conn.execute(statement, ()).await.expect("v23 statement");
    }
    for statement in V23_DNS_ADD_COLUMNS {
        conn.execute(statement, ()).await.expect("v23 column");
    }
    for table in ["dns_sources", "dns_resolvers", "dns_source_resolvers"] {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                (table,),
            )
            .await
            .expect("table lookup");
        let row = rows.next().await.expect("query").expect("one row");
        assert_eq!(
            row.get::<i64>(0).expect("count"),
            1,
            "table {table} must exist"
        );
    }
    let mut rows = conn
        .query("PRAGMA table_info(dns_settings)", ())
        .await
        .expect("columns");
    let mut columns = Vec::new();
    while let Some(row) = rows.next().await.expect("query") {
        columns.push(row.get::<String>(1).expect("column name"));
    }
    assert!(columns.iter().any(|c| c == "resolver_pool_size"));
    assert!(columns.iter().any(|c| c == "resolver_test_domain"));
}

/// The indexes are `IF NOT EXISTS` because `ensure_raw_ddl` runs them on every
/// open — a fresh file (`push_schema`) and a migrated one both get them, and a
/// second run must be a no-op.
#[tokio::test]
async fn the_indexes_are_idempotent() {
    let (_dir, db) = v22_fixture().await;
    let conn = db.connect().expect("connection");
    for statement in V23_DNS_SOURCES {
        conn.execute(statement, ()).await.expect("v23 statement");
    }
    for statement in V23_DNS_ADD_COLUMNS {
        conn.execute(statement, ()).await.expect("v23 column");
    }
    for statement in V23_DNS_INDEXES {
        conn.execute(statement, ()).await.expect("first index run");
    }
    for statement in V23_DNS_INDEXES {
        conn.execute(statement, ()).await.expect("second index run");
    }
    // The URL index is the uniqueness rule the app relies on.
    assert!(
        conn.execute(
            "INSERT INTO dns_sources (id, name, url, enabled, user_agent, sort_order, \
             last_refreshed, status, error_message, refresh_interval) \
             VALUES ('a', NULL, 'https://x/', 1, NULL, NULL, NULL, NULL, NULL, NULL)",
            (),
        )
        .await
        .is_ok()
    );
    assert!(
        conn.execute(
            "INSERT INTO dns_sources (id, name, url, enabled, user_agent, sort_order, \
             last_refreshed, status, error_message, refresh_interval) \
             VALUES ('b', NULL, 'https://x/', 1, NULL, NULL, NULL, NULL, NULL, NULL)",
            (),
        )
        .await
        .is_err(),
        "a second row for one URL must be refused"
    );
}
