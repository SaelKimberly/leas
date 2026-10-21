//! The migration runner's contract (`crate::schema`).
//!
//! These pin the four outcomes that replaced the old "tag matches or the file
//! is deleted" rule: a current file is a NO-OP, a fresh file is created, an
//! already-migrated file survives a reopen untouched, and a file whose cursor
//! names an unknown schema is reported as incompatible (so the caller can apply
//! its wipe) rather than silently mangled.

use leas_db::{Database, SCHEMA_VERSION, models::Endpoint, models::EndpointId, models::HostType};
use toasty::stmt::Value;

fn first_i64(rows: &[Value]) -> Option<i64> {
    rows.first().and_then(|v| match v {
        Value::Record(fields) => fields.first().and_then(|f| match f {
            Value::I64(n) => Some(*n),
            _ => None,
        }),
        _ => None,
    })
}

/// A FRESH file is created at the current version and gets the raw DDL (the
/// `endpoint_rank` columns and indexes toasty cannot express).
#[tokio::test]
async fn fresh_open_creates_tables_and_raw_ddl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::open(dir.path().join("fresh.db"))
        .await
        .expect("open");
    let mut conn = db.connection().await.expect("conn");

    let rows = toasty::sql::query("PRAGMA user_version")
        .exec(&mut conn)
        .await
        .expect("version");
    assert_eq!(first_i64(&rows), Some(SCHEMA_VERSION));

    // The raw columns the runner adds: neither is a toasty model field.
    for column in ["band", "rank_weight"] {
        let rows = toasty::sql::query(format!(
            "SELECT COUNT(*) FROM pragma_table_info('endpoint_rank') WHERE name = '{column}'"
        ))
        .exec(&mut conn)
        .await
        .expect("table_info");
        assert_eq!(first_i64(&rows), Some(1), "endpoint_rank.{column} exists");
    }
    // And the raw indexes (C2: composite / mixed-direction).
    let rows = toasty::sql::query(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
         AND name IN ('endpoint_rank_key_v2', 'endpoint_rank_band_window', 'endpoint_ip_by_key')",
    )
    .exec(&mut conn)
    .await
    .expect("count indexes");
    assert_eq!(first_i64(&rows), Some(3), "the three raw indexes exist");
}

/// Reopening a CURRENT file is a no-op: the rows survive, and the runner does
/// not re-run `CREATE TABLE` (which has no `IF NOT EXISTS` and would fail).
#[tokio::test]
async fn reopen_of_a_current_file_preserves_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("current.db");

    {
        let db = Database::open(&path).await.expect("fresh open");
        let mut conn = db.connection().await.expect("conn");
        toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(31),
            domain: Endpoint::derive_domain("keep.example", HostType::Dns).0,
            sub_domain: Endpoint::derive_domain("keep.example", HostType::Dns).1,
            port: 443,
            ports: Vec::<u16>::new(),
        })
        .exec(&mut conn)
        .await
        .expect("seed");
    }

    // Reopen: cursor == LATEST, so the runner ensures the (idempotent) raw DDL
    // and returns — no wipe, no failed `CREATE TABLE`.
    let db = Database::open(&path).await.expect("reopen");
    let mut conn = db.connection().await.expect("conn");
    let kept = Endpoint::filter_by_id(EndpointId::new(31))
        .first()
        .exec(&mut conn)
        .await
        .expect("read");
    assert!(kept.is_some(), "a current-version reopen preserves data");

    let rows = toasty::sql::query("PRAGMA user_version")
        .exec(&mut conn)
        .await
        .expect("version");
    assert_eq!(first_i64(&rows), Some(SCHEMA_VERSION));
}

/// Reopening an ALREADY-MIGRATED file re-applies the raw DDL idempotently — in
/// particular the two `ALTER TABLE ADD COLUMN`s, which have no
/// `IF NOT EXISTS` and whose duplicate-column error the runner must tolerate
/// (not propagate, which would make every reopen fail).
#[tokio::test]
async fn reopen_tolerates_duplicate_column_on_already_migrated_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen.db");

    for _ in 0..3 {
        let db = Database::open(&path)
            .await
            .expect("each open must succeed — a tolerated duplicate-column ALTER");
        let mut conn = db.connection().await.expect("conn");
        let rows = toasty::sql::query(
            "SELECT COUNT(*) FROM pragma_table_info('endpoint_rank') \
             WHERE name IN ('band', 'rank_weight')",
        )
        .exec(&mut conn)
        .await
        .expect("table_info");
        assert_eq!(first_i64(&rows), Some(2), "both raw columns still present");
        drop(conn);
        drop(db);
    }
}

/// A file whose cursor names a schema this build does not know is recreated by
/// `open` (the pre-alpha wipe), NOT migrated. `17` is a pre-migration tag: the
/// old `user_version` world where 1..17 were unrelated schemas.
#[tokio::test]
async fn unknown_cursor_is_recreated_not_migrated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("foreign.db");

    {
        let db = Database::open(&path).await.expect("fresh open");
        let mut conn = db.connection().await.expect("conn");
        toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(41),
            domain: Endpoint::derive_domain("gone.example", HostType::Dns).0,
            sub_domain: Endpoint::derive_domain("gone.example", HostType::Dns).1,
            port: 443,
            ports: Vec::<u16>::new(),
        })
        .exec(&mut conn)
        .await
        .expect("seed");
        // Pretend a previous schema generation wrote the file.
        toasty::sql::query("PRAGMA user_version = 17")
            .exec(&mut conn)
            .await
            .expect("tag");
    }

    let db = Database::open(&path).await.expect("reopen wipes");
    let mut conn = db.connection().await.expect("conn");
    let rows = toasty::sql::query("PRAGMA user_version")
        .exec(&mut conn)
        .await
        .expect("version");
    assert_eq!(
        first_i64(&rows),
        Some(SCHEMA_VERSION),
        "the file is rebuilt at the current version"
    );
    assert!(
        Endpoint::filter_by_id(EndpointId::new(41))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .is_none(),
        "an unknown cursor is a wipe, not a migration"
    );
}

/// The seed is keyed on a DURABLE STAMP, not on "did the ALTER run".
///
/// The earlier form fired only on the open that ADDED the column, so a process
/// killed between the ALTER and the seed left every pre-upgrade success with an
/// empty ring — and every later open saw "duplicate column" and skipped the
/// seed forever, stranding those endpoints outside all four scoped menus. This
/// test performs exactly that partial upgrade and proves the next open heals it.
#[tokio::test]
async fn a_seed_lost_to_a_crash_is_rerun_on_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("crash.db");
    {
        let db = Database::open(&path).await.expect("open");
        let mut conn = db.connection().await.expect("conn");
        let (domain, sub_domain) = Endpoint::derive_domain("198.51.100.9", HostType::Ipv4);
        toasty::create!(Endpoint {
            id: EndpointId::new(9),
            domain,
            sub_domain,
            port: 443,
            ports: Vec::<u16>::new(),
            created_at: 0,
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
        })
        .exec(&mut conn)
        .await
        .expect("endpoint");
        toasty::sql::statement(
            "INSERT INTO protocols (id, sig, proto_kind, transport_type, security_type, \
             security_sni, security_fp, security_insecure, config, created_at) \
             VALUES (901, 901, 'vless', 'tcp', 'none', NULL, NULL, NULL, 'null', 0)",
        )
        .exec(&mut conn)
        .await
        .expect("protocol");
        toasty::sql::statement(
            "INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, \
             latency_real_delay, latency_fast_delay, latency_ip, latency_auth, speed_bps, \
             traffic_today_up, traffic_today_down, traffic_total_up, \
             traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) \
             VALUES (901, 9, 0, 42, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 1, 0, 0)",
        )
        .exec(&mut conn)
        .await
        .expect("link");
        // Simulate the interrupted upgrade: the columns exist (as if the ALTER
        // had run) but no seed and NO STAMP was ever written.
        toasty::sql::statement("DELETE FROM app_meta WHERE key = 'stability_seeded_v2'")
            .exec(&mut conn)
            .await
            .expect("unstamped");
    }

    let db = Database::open(&path).await.expect("reopen");
    let mut conn = db.connection().await.expect("conn");
    let ring: Vec<(i64, i64)> = {
        let rows = toasty::sql::query(
            "SELECT stab_mask, stab_len FROM profile_stats WHERE endpoint_id = 9",
        )
        .exec(&mut conn)
        .await
        .expect("read ring");
        rows.iter()
            .filter_map(|v| match v {
                Value::Record(rec) => match (&rec.fields[0], &rec.fields[1]) {
                    (Value::I64(a), Value::I64(b)) => Some((*a, *b)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        ring,
        vec![(1, 1)],
        "the lost seed is re-run: the surviving real latency is seeded on reopen"
    );
}

/// The seed runs at most ONCE: a second open must not touch the rings (a live
/// link's ring is the probe path's to maintain).
#[tokio::test]
async fn the_stability_seed_runs_once_and_is_stamped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("once.db");
    let db = Database::open(&path).await.expect("open");
    let mut conn = db.connection().await.expect("conn");
    let stamp =
        toasty::sql::query("SELECT COUNT(*) FROM app_meta WHERE key = 'stability_seeded_v2'")
            .exec(&mut conn)
            .await
            .expect("stamp");
    assert_eq!(first_i64(&stamp), Some(1), "the seed stamps itself");
    drop(conn);
    drop(db);

    let db = Database::open(&path).await.expect("reopen");
    let mut conn = db.connection().await.expect("conn");
    let stamp2 =
        toasty::sql::query("SELECT COUNT(*) FROM app_meta WHERE key = 'stability_seeded_v2'")
            .exec(&mut conn)
            .await
            .expect("stamp");
    assert_eq!(first_i64(&stamp2), Some(1), "the stamp is a single row");
}

/// The day-one stability seed (spec `2026-10-09-stab-bin-design` §6.2).
///
/// An existing database's rings are empty, but `apply_test_result` KEEPS
/// `latency` when it later writes an error — so every previously-successful
/// link carries a real latency with no ring, and under R1 those endpoints would
/// match NO scope. The seed gives such a link a one-sample success ring, which
/// makes `rank_proven` true and the window neutral (one sample < `STAB_WARMUP`).
#[tokio::test]
async fn the_stab_seed_marks_real_latency_links_as_proven() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seed.db");
    {
        let db = Database::open(&path).await.expect("open");
        let mut conn = db.connection().await.expect("conn");
        // Two endpoints, one with a REAL latency (a past success) and one with a
        // FAST one (a handshake, which proves nothing).
        // IP-literal hosts: a DNS host with no resolved address is deliberately
        // NOT provable (it cannot be dialled), so it would mask the seed.
        for (id, host, port) in [(1_i64, "198.51.100.1", 443_u16), (2, "198.51.100.2", 8443)] {
            let (domain, sub_domain) = Endpoint::derive_domain(host, HostType::Ipv4);
            toasty::create!(Endpoint {
                id: EndpointId::new(id),
                domain,
                sub_domain,
                port,
                ports: Vec::<u16>::new(),
                created_at: 0,
                last_source: None,
                manual_protocol_override: None,
                resolved_at: None,
            })
            .exec(&mut conn)
            .await
            .expect("endpoint");
        }
        // The 'real' row carries a REAL delay; the 'fast' one a TRANSPORT
        // delay. Schema 19: the provenance is which delay column is populated.
        for (pid, eid, real_delay, fast_delay) in [
            (101_i64, 1_i64, Some(42_i64), None),
            (102, 2, None, Some(42)),
        ] {
            let real = real_delay.map_or_else(|| "NULL".to_owned(), |d| d.to_string());
            let fast = fast_delay.map_or_else(|| "NULL".to_owned(), |d| d.to_string());
            toasty::sql::statement(format!(
                "INSERT INTO protocols (id, sig, proto_kind, transport_type, \
                 security_type, security_sni, security_fp, security_insecure, config, \
                 created_at) VALUES ({pid}, {pid}, 'vless', 'tcp', 'none', NULL, NULL, \
                 NULL, 'null', 0)"
            ))
            .exec(&mut conn)
            .await
            .expect("protocol");
            toasty::sql::statement(format!(
                "INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, \
                 latency_real_delay, latency_fast_delay, latency_ip, latency_auth, speed_bps, \
                 traffic_today_up, traffic_today_down, traffic_total_up, traffic_total_down, \
                 created_at, updated_at, version, stab_mask, stab_len) VALUES \
                 ({pid}, {eid}, 0, {real}, {fast}, NULL, NULL, NULL, 0, 0, 0, 0, \
                 0, 0, 1, 0, 0)"
            ))
            .exec(&mut conn)
            .await
            .expect("link");
        }
        // Simulate the pre-seed state: drop the ring columns AND clear the
        // stamp, so the next open re-adds them and the seed fires. (An existing
        // table is exactly the case the ALTER path exists for; the stamp is
        // what the seed is now keyed on, so an interrupted upgrade has to clear
        // it too.)
        toasty::sql::statement("ALTER TABLE profile_stats DROP COLUMN stab_mask")
            .exec(&mut conn)
            .await
            .expect("drop stab_mask");
        toasty::sql::statement("ALTER TABLE profile_stats DROP COLUMN stab_len")
            .exec(&mut conn)
            .await
            .expect("drop stab_len");
        toasty::sql::statement("DELETE FROM app_meta WHERE key = 'stability_seeded_v2'")
            .exec(&mut conn)
            .await
            .expect("clear the seed stamp");
    }

    let db = Database::open(&path).await.expect("reopen");
    let mut conn = db.connection().await.expect("conn");
    let rows = toasty::sql::query(
        "SELECT endpoint_id, stab_mask, stab_len FROM profile_stats ORDER BY endpoint_id",
    )
    .exec(&mut conn)
    .await
    .expect("read rings");
    let as_triple = |v: &Value| match v {
        Value::Record(rec) => match (&rec.fields[0], &rec.fields[1], &rec.fields[2]) {
            (Value::I64(id), Value::I64(mask), Value::I64(len)) => Some((*id, *mask, *len)),
            _ => None,
        },
        _ => None,
    };
    let triples: Vec<(i64, i64, i64)> = rows.iter().filter_map(as_triple).collect();
    assert_eq!(
        triples,
        vec![(1, 1, 1), (2, 0, 0)],
        "a real latency seeds one success; a fast one seeds nothing"
    );

    let proven: i64 = first_i64(
        &toasty::sql::query(
            "SELECT COUNT(*) FROM endpoint_rank WHERE rank_proven = 1 AND endpoint_id = 1",
        )
        .exec(&mut conn)
        .await
        .expect("count proven"),
    )
    .unwrap_or(0);
    assert_eq!(
        proven, 1,
        "the seeded endpoint is proven after the rank refresh"
    );
    let stray: i64 = first_i64(
        &toasty::sql::query(
            "SELECT COUNT(*) FROM endpoint_rank WHERE rank_proven = 1 AND endpoint_id = 2",
        )
        .exec(&mut conn)
        .await
        .expect("count stray"),
    )
    .unwrap_or(0);
    assert_eq!(stray, 0, "the fast-only endpoint must NOT become proven");

    // The end-to-end claim (spec acceptance 6): after the upgrade the
    // previously-successful endpoint is STILL in the Successful scope, not
    // dropped out of it because its ring was empty.
    let req = leas_db::profiles_query::PageRequest {
        // `All`: these fixture links are stamped at epoch 0, so the Active
        // window (measured against `now - ttl`) does not hold them.
        view: leas_db::models::PurgatoryView::All,
        active_threshold: 0,
        search: None,
        group_id: None,
        scope: leas_db::profiles_query::PlanScope::Successful,
        sort: leas_db::profiles_query::PageSort::Test,
        ascending: true,
        offset: 0,
        limit: 100,
    };
    let page = db.profiles_page(&req).await.expect("successful page");
    assert_eq!(
        page.total, 1,
        "the seeded endpoint is the Successful scope's only member"
    );
    assert_eq!(
        page.ids.iter().map(|id| id.get()).collect::<Vec<_>>(),
        vec![1],
        "and it is the REAL-latency endpoint, not the fast-only one"
    );
}

// ── Migration 19: the latency reshape (spec 2026-10-21 D5, ADR 0016) ─────
//
// The `Latency` embed was an ENUM with a shared `delay` column and an
// exclusive discriminator, so a row could hold a real delay OR a fast delay,
// never both. The merged probe produces both in one pass, so the embed became
// a STRUCT and the discriminator was dropped.
//
// These pin the migration's contract:
//   * a version-18 database migrates in place and reads back with the SAME
//     numbers — a 'real' row's delay in `latency_real_delay`, a 'fast' row's
//     in `latency_fast_delay`;
//   * the RENAME and the DROP are NOT idempotent, so a REOPEN must not re-run
//     them (the cursor gates the step; a second application would fail with
//     "no such column");
//   * a foreign cursor is still reported as incompatible (the wipe).

/// A version-18 file: the v18 shape (`latency` discriminator + shared
/// `latency_delay`), with one 'real' row and one 'fast' row.
async fn seed_a_v18_database(path: &std::path::Path) {
    let db = Database::open(path).await.expect("fresh open");
    let mut conn = db.connection().await.expect("conn");

    for (id, host, port) in [(1_i64, "198.51.100.1", 443_u16), (2, "198.51.100.2", 8443)] {
        let (domain, sub_domain) = Endpoint::derive_domain(host, HostType::Ipv4);
        toasty::create!(Endpoint {
            id: EndpointId::new(id),
            domain,
            sub_domain,
            port,
            ports: Vec::<u16>::new(),
            created_at: 0,
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
        })
        .exec(&mut conn)
        .await
        .expect("endpoint");
    }
    // The rows are written in the CURRENT shape (the file starts at the
    // current version), and the SCHEMA is rolled back below.
    for (pid, eid, real_delay, fast_delay) in [
        (101_i64, 1_i64, Some(140_i64), None),
        (102, 2, None, Some(12)),
    ] {
        let real = real_delay.map_or_else(|| "NULL".to_owned(), |d| d.to_string());
        let fast = fast_delay.map_or_else(|| "NULL".to_owned(), |d| d.to_string());
        toasty::sql::statement(format!(
            "INSERT INTO protocols (id, sig, proto_kind, transport_type, \
             security_type, security_sni, security_fp, security_insecure, config, \
             created_at) VALUES ({pid}, {pid}, 'vless', 'tcp', 'none', NULL, NULL, \
             NULL, 'null', 0)"
        ))
        .exec(&mut conn)
        .await
        .expect("protocol");
        toasty::sql::statement(format!(
            "INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, \
             latency_real_delay, latency_fast_delay, latency_ip, latency_auth, speed_bps, \
             traffic_today_up, traffic_today_down, traffic_total_up, traffic_total_down, \
             created_at, updated_at, version, stab_mask, stab_len) VALUES \
             ({pid}, {eid}, 0, {real}, {fast}, NULL, NULL, NULL, 0, 0, 0, 0, \
             0, 0, 1, 0, 0)"
        ))
        .exec(&mut conn)
        .await
        .expect("link");
    }

    // Roll the file back to the v18 shape. The ORDER matters:
    //   1. the real delay is renamed back to `latency_delay` (the v18 column
    //      name — it does not exist until the rename);
    //   2. the discriminator column is added (the UPDATE writes it);
    //   3. the v18 values are restored — the v18 shape stored the delay ONCE,
    //      in `latency_delay`, and the discriminator said which kind it was, so
    //      the fast row's delay is copied into the same column;
    //   4. the v19-only columns are dropped.
    toasty::sql::statement(
        "ALTER TABLE profile_stats RENAME COLUMN latency_real_delay TO latency_delay",
    )
    .exec(&mut conn)
    .await
    .expect("rename the real delay back");
    toasty::sql::statement("ALTER TABLE profile_stats ADD COLUMN latency TEXT")
        .exec(&mut conn)
        .await
        .expect("add the discriminator back");
    toasty::sql::statement(
        "UPDATE profile_stats SET latency = CASE \
           WHEN latency_delay IS NOT NULL AND latency_fast_delay IS NULL THEN 'real' \
           WHEN latency_delay IS NULL AND latency_fast_delay IS NOT NULL THEN 'fast' \
           ELSE '' END, \
         latency_delay = COALESCE(latency_delay, latency_fast_delay)",
    )
    .exec(&mut conn)
    .await
    .expect("restore the v18 values");
    toasty::sql::statement("ALTER TABLE profile_stats DROP COLUMN latency_fast_delay")
        .exec(&mut conn)
        .await
        .expect("drop fast_delay");
    toasty::sql::statement("ALTER TABLE profile_stats DROP COLUMN latency_auth")
        .exec(&mut conn)
        .await
        .expect("drop auth");
    toasty::sql::query("PRAGMA user_version = 18")
        .exec(&mut conn)
        .await
        .expect("set cursor");
}

/// A version-18 database migrates in place: the numbers survive, and each
/// row's delay lands in the column its provenance says it belongs in.
#[tokio::test]
async fn a_v18_database_migrates_and_keeps_its_numbers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v18.db");
    seed_a_v18_database(&path).await;

    let db = Database::open(&path).await.expect("migrating open");
    let mut conn = db.connection().await.expect("conn");

    let rows = toasty::sql::query(
        "SELECT endpoint_id, latency_real_delay, latency_fast_delay FROM profile_stats \
         ORDER BY endpoint_id",
    )
    .exec(&mut conn)
    .await
    .expect("read");

    let read = |v: &Value| -> Option<(i64, Option<i64>, Option<i64>)> {
        match v {
            Value::Record(rec) => match (&rec.fields[0], &rec.fields[1], &rec.fields[2]) {
                (Value::I64(id), Value::I64(real), Value::I64(fast)) => {
                    Some((*id, Some(*real), Some(*fast)))
                }
                (Value::I64(id), Value::Null, Value::I64(fast)) => Some((*id, None, Some(*fast))),
                (Value::I64(id), Value::I64(real), Value::Null) => Some((*id, Some(*real), None)),
                (Value::I64(id), Value::Null, Value::Null) => Some((*id, None, None)),
                _ => None,
            },
            _ => None,
        }
    };
    let rows: Vec<(i64, Option<i64>, Option<i64>)> = rows.iter().filter_map(read).collect();

    assert_eq!(
        rows,
        vec![(1, Some(140), None), (2, None, Some(12))],
        "the 'real' row's delay moved to latency_real_delay and the 'fast' row's \
         to latency_fast_delay — the numbers themselves are unchanged"
    );
}

/// The discriminator is GONE: the row's provenance is now carried by which
/// delay column is populated, not by a separate column.
#[tokio::test]
async fn the_migrated_table_has_no_latency_discriminator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v18-nodisc.db");
    seed_a_v18_database(&path).await;

    let db = Database::open(&path).await.expect("migrating open");
    let mut conn = db.connection().await.expect("conn");

    let rows = toasty::sql::query(
        "SELECT COUNT(*) FROM pragma_table_info('profile_stats') WHERE name = 'latency'",
    )
    .exec(&mut conn)
    .await
    .expect("table_info");
    assert_eq!(
        first_i64(&rows),
        Some(0),
        "the discriminator column is dropped, not kept alongside the two delays"
    );

    for column in [
        "latency_real_delay",
        "latency_fast_delay",
        "latency_ip",
        "latency_auth",
    ] {
        let rows = toasty::sql::query(format!(
            "SELECT COUNT(*) FROM pragma_table_info('profile_stats') WHERE name = '{column}'"
        ))
        .exec(&mut conn)
        .await
        .expect("table_info");
        assert_eq!(first_i64(&rows), Some(1), "profile_stats.{column} exists");
    }
}

/// The RENAME and the DROP are NOT idempotent — a second application fails
/// with "no such column". The cursor is what makes them safe, so a REOPEN of
/// a migrated file must not re-run them.
#[tokio::test]
async fn reopening_a_migrated_file_does_not_re_run_the_non_idempotent_step() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen19.db");
    seed_a_v18_database(&path).await;

    for round in 0..3 {
        let db = Database::open(&path).await.unwrap_or_else(|e| {
            panic!("round {round}: a reopen must not re-run the RENAME: {e:?}")
        });
        let mut conn = db.connection().await.expect("conn");
        let rows = toasty::sql::query("PRAGMA user_version")
            .exec(&mut conn)
            .await
            .expect("version");
        assert_eq!(first_i64(&rows), Some(SCHEMA_VERSION));
        let rows = toasty::sql::query(
            "SELECT COUNT(*) FROM pragma_table_info('profile_stats') WHERE name = 'latency'",
        )
        .exec(&mut conn)
        .await
        .expect("table_info");
        assert_eq!(first_i64(&rows), Some(0), "the discriminator stays dropped");
    }
}
