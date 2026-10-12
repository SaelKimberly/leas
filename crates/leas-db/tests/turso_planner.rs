//! T2 (db-rewamp plan): the **turso** planner gate for the proposed rank-key
//! index.
//!
//! The design spec's §9 numbers were measured with the SQLite planner
//! (python `sqlite3`) on a copy of `data.db`; production runs **turso 0.7.2**,
//! whose planner is its own. Before any §9 number is quoted as production
//! truth, the exact proposed shape must be shown to be picked by turso.
//!
//! This test builds the PROPOSED `endpoint_rank` columns and the raw
//! `endpoint_rank_key` covering index in a scratch turso database, seeds it at
//! reference scale, and prints `EXPLAIN QUERY PLAN` for the three page paths
//! plus the two traps (`band IN (0,1)` must filesort; the scope-bin scan and
//! the reband range must be index-served).
//!
//! Ignored by default — it is a perf/planner gate, not a CI test.
//!
//! ```text
//! cargo test -p leas-db --release --test turso_planner -- --ignored --nocapture
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
#![allow(
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::significant_drop_tightening,
    clippy::used_underscore_binding
)]
use turso::Builder;

/// Reference-feed scale (the 2026-10-06 `data.db` endpoint count).
const N: usize = 74_723;

/// The covering index the shipped schema uses (`endpoint_rank_key`, v18) —
/// `rank_stab` between the bin and the weight, `rank_proven` TRAILING.
const KEY_INDEX: &str = "CREATE INDEX endpoint_rank_key ON endpoint_rank(\
     band, rank_bin, rank_stab, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, \
     endpoint_id, rank_proven)";

/// The ORDER BY term list (the binned law), band-less so the same text serves
/// the Active/Purgatory seek and the All `(band, key)` scan.
const KEY: &str = "band, rank_bin, rank_stab, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, endpoint_id";

fn value_row(i: usize) -> String {
    let band = i64::from(!(i % 10).is_multiple_of(10));
    let bin = (i % 18) as i64;
    // A descending 8-byte BE blob, the real column's shape.
    let weight = format!("x'{:016x}'", u64::MAX - (i as u64 % 1000));
    let domain = format!("d{}", i % 5000);
    let sub = format!("s{}", i % 200);
    let addr = format!("x'04{:08x}'", (i as u32) & 0x00ff_ffff);
    let seen = 1_700_000_000i64 + (i as i64 % 100_000);
    // One in four proven, and a stability bin spread so the index's third term
    // is not constant (a constant column cannot mask a missing term, but a
    // spread one makes a wrong column ORDER show up in the plan).
    let stab = (i % 8) as i64;
    let proven = i64::from(i % 4 == 0);
    format!("({i},{band},{bin},{weight},'{domain}','{sub}',{addr},{seen},{stab},{proven})")
}

async fn plan(conn: &turso::Connection, sql: &str) -> Vec<String> {
    let mut rows = conn
        .query(format!("EXPLAIN QUERY PLAN {sql}"), ())
        .await
        .expect("explain");
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.expect("row") {
        // SQLite/turso EXPLAIN QUERY PLAN: (id, parent, notused, detail).
        let detail = (0..)
            .find_map(|i| row.get::<String>(i).ok())
            .unwrap_or_default();
        out.push(detail);
    }
    out
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "turso planner gate (db-rewamp T2); prints plans, not an assertion suite"]
async fn turso_planner_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("planner.db");
    let db = Builder::new_local(path.to_str().expect("path"))
        .build()
        .await
        .expect("build");
    let conn = db.connect().expect("connect");

    conn.execute(
        "CREATE TABLE endpoint_rank (\
         endpoint_id INTEGER PRIMARY KEY, band INTEGER NOT NULL, rank_bin INTEGER NOT NULL, \
         rank_weight BLOB NOT NULL, rank_domain TEXT NOT NULL, rank_sub_domain TEXT NOT NULL, \
         rank_addr BLOB NOT NULL, rank_newest_seen INTEGER NOT NULL, \
         rank_stab INTEGER NOT NULL, rank_proven INTEGER NOT NULL)",
        (),
    )
    .await
    .expect("create");

    // Seed in chunks (a single 74k-row VALUES tuple would blow the parser).
    let ids: Vec<usize> = (0..N).collect();
    for chunk in ids.chunks(5000) {
        let values = chunk
            .iter()
            .map(|&i| value_row(i))
            .collect::<Vec<_>>()
            .join(",");
        conn.execute(format!("INSERT INTO endpoint_rank VALUES {values}"), ())
            .await
            .expect("seed");
    }
    conn.execute(
        "CREATE INDEX endpoint_rank_window ON endpoint_rank(band, rank_newest_seen)",
        (),
    )
    .await
    .expect("window index");
    conn.execute(KEY_INDEX, ()).await.expect("key index");

    // Queries: the three page paths + the two traps.
    let cases: [(&str, String); 5] = [
        (
            "Active band=0 seek",
            format!(
                "SELECT endpoint_id FROM endpoint_rank WHERE band=0 ORDER BY {KEY} LIMIT 200 OFFSET 5000"
            ),
        ),
        (
            "Purgatory band=1 seek",
            format!(
                "SELECT endpoint_id FROM endpoint_rank WHERE band=1 ORDER BY {KEY} LIMIT 200 OFFSET 5000"
            ),
        ),
        (
            "All ORDER band,key (wanted)",
            format!(
                "SELECT endpoint_id FROM endpoint_rank WHERE 1=1 ORDER BY {KEY} LIMIT 200 OFFSET 5000"
            ),
        ),
        (
            "All band IN (0,1) key (trap)",
            format!(
                "SELECT endpoint_id FROM endpoint_rank WHERE band IN (0,1) ORDER BY {KEY} LIMIT 200 OFFSET 5000"
            ),
        ),
        (
            "scope rank_bin IN (13,14,15)",
            format!(
                "SELECT endpoint_id FROM endpoint_rank WHERE rank_bin IN (13,14,15) ORDER BY {KEY} LIMIT 200"
            ),
        ),
    ];

    for (label, sql) in cases {
        let p = plan(&conn, &sql).await;
        let sorted = p.iter().any(|s| s.to_lowercase().contains("temp b-tree"));
        println!("\n[{label}]\n  {p:?}\n  temp-b-tree={sorted}");
    }
    // The reband sweep's range — must be an index range, no scan of the table.
    let p = plan(
        &conn,
        "UPDATE endpoint_rank SET band=1 WHERE band=0 AND rank_newest_seen < 100",
    )
    .await;
    println!("\n[reband sweep]\n  {p:?}");
}

/// The planner ASSERTION the design's acceptance 5 rests on (spec
/// `2026-10-09-stab-bin-design` R5): every scope is an index seek or scan with
/// NO sorter, `rank_proven` being a TRAILING covering column.
///
/// This is the regression the trailing placement exists for: move
/// `rank_proven` between `band` and the order terms and the two scoped cases
/// below acquire a `USE TEMP B-TREE FOR ORDER BY`.
#[tokio::test(flavor = "current_thread")]
async fn every_scope_plan_is_index_served_without_a_sorter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("planner_assert.db");
    let db = Builder::new_local(path.to_str().expect("path"))
        .build()
        .await
        .expect("build");
    let conn = db.connect().expect("connect");
    conn.execute(
        "CREATE TABLE endpoint_rank (\
         endpoint_id INTEGER PRIMARY KEY, band INTEGER NOT NULL, rank_bin INTEGER NOT NULL, \
         rank_weight BLOB NOT NULL, rank_domain TEXT NOT NULL, rank_sub_domain TEXT NOT NULL, \
         rank_addr BLOB NOT NULL, rank_newest_seen INTEGER NOT NULL, \
         rank_stab INTEGER NOT NULL, rank_proven INTEGER NOT NULL)",
        (),
    )
    .await
    .expect("create");
    // Small but non-trivial: enough rows that a filesort is chosen if one is
    // possible, cheap enough to seed on every run.
    let ids: Vec<usize> = (0..8_000).collect();
    let values = ids
        .iter()
        .map(|&i| value_row(i))
        .collect::<Vec<_>>()
        .join(",");
    conn.execute(format!("INSERT INTO endpoint_rank VALUES {values}"), ())
        .await
        .expect("seed");
    conn.execute(KEY_INDEX, ()).await.expect("key index");

    let scope_cases = [
        ("Active", "band = 0", ""),
        ("Purgatory", "band = 1", ""),
        ("Successful", "band = 0", " AND rank_proven = 1"),
        ("New", "band = 0", " AND rank_proven = 0 AND rank_bin = 12"),
        (
            "Failed",
            "band = 0",
            " AND rank_proven = 0 AND rank_bin IN (13,14,15)",
        ),
        (
            "SuccessfulAndNew",
            "band = 0",
            " AND (rank_proven = 1 OR rank_bin = 12)",
        ),
    ];
    for (label, band, extra) in scope_cases {
        let sql = format!(
            "SELECT endpoint_id FROM endpoint_rank WHERE {band}{extra} ORDER BY {KEY} LIMIT 200"
        );
        let p = plan(&conn, &sql).await;
        let joined = p.join(" | ").to_lowercase();
        assert!(
            !joined.contains("temp b-tree") && !joined.contains("sorter"),
            "{label}: the scope must not filesort, plan was {p:?}"
        );
    }

    // The unstricted All view: the index order IS the ORDER BY, no sorter.
    let all = plan(
        &conn,
        &format!("SELECT endpoint_id FROM endpoint_rank ORDER BY {KEY} LIMIT 200"),
    )
    .await;
    let joined = all.join(" | ").to_lowercase();
    assert!(
        !joined.contains("temp b-tree") && !joined.contains("sorter"),
        "All must scan in index order, plan was {all:?}"
    );
}

/// T14 gate: does turso 0.7.2 actually support `WITHOUT ROWID` behind its
/// experimental flag, and does it round-trip data through it?
///
/// The design defers WITHOUT ROWID (5 integer-key tables ≈ −4.9% disk) unless
/// this proves the engine honours it end-to-end — the SQLite-planner disk
/// numbers alone are not enough, because turso's implementation is
/// experimental and default-off.
#[tokio::test(flavor = "current_thread")]
#[ignore = "turso capability gate (db-rewamp T14)"]
async fn turso_without_rowid_support() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wr.db");
    // Default builder: the flag is OFF.
    let db_off = Builder::new_local(path.to_str().expect("path"))
        .build()
        .await
        .expect("build off");
    let conn_off = db_off.connect().expect("connect off");
    let err = conn_off
        .execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID",
            (),
        )
        .await;
    println!("[flag OFF] CREATE ... WITHOUT ROWID -> {err:?}");

    let dir2 = tempfile::tempdir().expect("tempdir");
    let path2 = dir2.path().join("wron.db");
    let db_on = Builder::new_local(path2.to_str().expect("path"))
        .experimental_without_rowid(true)
        .build()
        .await
        .expect("build on");
    let conn_on = db_on.connect().expect("connect on");
    let create = conn_on
        .execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID",
            (),
        )
        .await;
    println!("[flag ON ] CREATE ... WITHOUT ROWID -> {create:?}");
    assert!(create.is_ok(), "flag ON must allow WITHOUT ROWID");

    conn_on
        .execute("INSERT INTO t VALUES (1, 'hello'), (2, 'world')", ())
        .await
        .expect("insert");
    let mut rows = conn_on
        .query("SELECT v FROM t WHERE id = 2", ())
        .await
        .expect("select");
    let row = rows.next().await.expect("next").expect("row");
    let v: String = row.get(0).expect("v");
    println!("[flag ON ] round-trip id=2 -> {v:?}");
    assert_eq!(v, "world", "WITHOUT ROWID round-trips");
    let mut rows = conn_on
        .query("SELECT id FROM t ORDER BY id DESC", ())
        .await
        .expect("ordered");
    let mut order = Vec::new();
    while let Some(r) = rows.next().await.expect("next") {
        order.push(r.get::<i64>(0).expect("id"));
    }
    println!("[flag ON ] ORDER BY id DESC -> {order:?}");
    assert_eq!(order, vec![2, 1], "ordered scan over a WITHOUT ROWID table");
    println!("\nVERDICT: turso honours WITHOUT ROWID behind experimental_without_rowid(true).");
}
