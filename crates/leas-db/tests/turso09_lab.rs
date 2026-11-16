#![cfg(feature = "perf-lab")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "lab arithmetic over a fixed feed size and a float percentile index"
)]
//! Research lab (2026-11-16): turso `0.9.0-pre.5` — WAL against MVCC across the
//! leas write/read workloads, with process-level CPU, peak RSS and on-disk bytes.
//!
//! Prints tables, asserts nothing. It answers three questions with numbers:
//!
//! 1. what the subscription-import burst costs in wall time, CPU, memory and
//!    disk under each journal mode;
//! 2. what a page reader sees WHILE that burst runs, against its own quiet
//!    baseline (the 39.6 s page read in the 2026-11-16 dump);
//! 3. what the orphan-protocol anti-join costs at feed scale — and what a
//!    `protocols`/`protocol_config` SPLIT would change, since the anti-join
//!    scans that table whole (508 s of 772 s of slow-query time in the dump).
//!
//! Statements are the bulk writers' own text (`upsert_endpoints_bulk` /
//! `upsert_links_bulk` inline their literals, so the engine sees identical SQL).
//! Protocols go through the typed per-row upsert, as `upsert_protocols_bulk`
//! does. `endpoint_rank::refresh` is not reproduced: it runs the same
//! `INSERT OR REPLACE` in both arms, so it is mode-neutral, and leaving it out
//! keeps each arm a clean measure of the journal mode.
//!
//! Run:
//! ```text
//! cargo test -p leas-db --release --features perf-lab --test turso09_lab -- --ignored --nocapture
//! ```

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use leas_db::Database;
use leas_db::models::{EndpointId, Protocol, ProtocolId, Security, Transport};
use leas_proto::proto_spec::common::TransportConfig;
use leas_proto::proto_spec::{
    ProtocolConfig, ProtocolKind, SecurityConfig, SecurityType, TransportType, VlessConfig,
};
use toasty::{Deferred, Json};

/// Rows per multi-row statement: what `IMPORT_STATEMENT_ROWS` /
/// `LINK_STATEMENT_ROWS` use.
const BATCH: usize = 400;
/// Feed size for the purge arm — the dump's own scale.
const FEED: usize = 74_000;
/// Protocol count for the insert-shape arm.
const PROTO_ROWS: usize = 20_000;

const ENDPOINT_COLS: &str = "INSERT INTO \"endpoints\" (\"id\", \"domain\", \"sub_domain\", \
     \"port\", \"ports\", \"last_source\", \"created_at\") VALUES ";

const LINK_COLS: &str = "INSERT INTO profile_stats (protocol_id, endpoint_id, \
     last_used_at, last_seen_at, latency_real_delay, latency_fast_delay, latency_ip, \
     latency_auth, speed_bps, \
     error, error_kind, error_text, purge_reason, traffic_today_up, traffic_today_down, \
     traffic_total_up, traffic_total_down, created_at, updated_at, version, \
     stab_mask, stab_len) VALUES ";

const LINK_CONFLICT: &str = " ON CONFLICT(protocol_id, endpoint_id) DO UPDATE SET \
     last_seen_at = excluded.last_seen_at, updated_at = excluded.updated_at";

/// Process CPU time in milliseconds (`utime + stime`, 100 ticks/s).
fn cpu_ms() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("stat");
    let rest = stat.rsplit_once(')').expect("comm paren").1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After `)` the first field is state (field 3), so utime (14) and stime (15)
    // are indexes 11 and 12 here.
    let ticks: u64 =
        fields[11].parse::<u64>().expect("utime") + fields[12].parse::<u64>().expect("stime");
    ticks * 10
}

/// Peak resident set size in KiB (`VmHWM`).
fn vmhwm_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("VmHWM")
}

const fn mib(kb: u64) -> u64 {
    kb / 1024
}

/// Bytes on disk, split by the engine's sidecar: the DB file, the WAL, and the
/// MVCC logical log (`<db>.db-log`).
fn disk(db: &Path) -> (u64, u64, u64) {
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let wal = db.with_file_name(format!(
        "{}-wal",
        db.file_name().expect("db name").to_string_lossy()
    ));
    let log = db.with_extension("db-log");
    (size(db), size(&wal), size(&log))
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() - 1) as f64 * p) as usize]
}

async fn open(dir: &Path, mvcc: bool) -> Arc<Database> {
    Arc::new(
        Database::open_with_concurrent_writes(dir.join("lab.db"), mvcc)
            .await
            .expect("open"),
    )
}

fn endpoint_tuple(id: usize) -> String {
    format!("({id}, 'd{id}.example', '', 443, '[]', 'src', 1)")
}

fn link_tuple(id: usize) -> String {
    format!(
        "({id}, {id}, NULL, 1, 12, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
         0, 0, 0, 0, 1, 1, 1, 0, 0)"
    )
}

/// A realistic VLESS definition: uuid + flow + remarks make the JSON config a
/// few hundred bytes, which is what makes `protocols` a WIDE table.
fn vless_cfg(i: usize, wide: bool) -> ProtocolConfig {
    if !wide {
        // The narrow shape a `protocols`/`protocol_config` split would leave
        // behind: identity and display scalars only.
        return ProtocolConfig::Vless(VlessConfig {
            uuid: String::new(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        });
    }
    ProtocolConfig::Vless(VlessConfig {
        uuid: format!("00000000-0000-4000-8000-{:012}", i % 1_000_000_000_000),
        uuid_origin: None,
        security: SecurityConfig::default(),
        transport: TransportConfig::Tcp,
        encryption: None,
        flow: Some("xtls-rprx-vision".into()),
        path: None,
        splice: None,
        remarks: Some(format!("node-{i}").into()),
        mux: None,
    })
}

/// One import burst: `BATCH`-row statements, one transaction per batch, the
/// shape `upsert_endpoints_bulk` / `upsert_links_bulk` issue. `with_links=false`
/// writes endpoints + protocols only (the purge arm's orphan tail).
async fn import_burst(db: &Database, from: usize, to: usize, with_links: bool, wide: bool) {
    let mut conn = db.connection().await.expect("conn");
    for start in (from..to).step_by(BATCH) {
        let end = (start + BATCH).min(to);
        let mut eps = String::with_capacity((end - start) * 48);
        let mut links = String::with_capacity((end - start) * 96);
        for i in start..end {
            if i > start {
                eps.push(',');
                links.push(',');
            }
            eps.push_str(&endpoint_tuple(i));
            links.push_str(&link_tuple(i));
        }
        let mut tx = conn.transaction().await.expect("tx");
        toasty::sql::statement(format!(
            "{ENDPOINT_COLS}{eps} ON CONFLICT(\"id\") DO UPDATE SET \
             \"domain\" = excluded.\"domain\", \"sub_domain\" = excluded.\"sub_domain\", \
             \"port\" = excluded.\"port\", \"ports\" = excluded.\"ports\", \
             \"last_source\" = excluded.\"last_source\""
        ))
        .exec(&mut tx)
        .await
        .expect("endpoints");
        // Protocols: `upsert_protocols_bulk` is ONE typed upsert per protocol
        // (it is not chunked), so this mirrors it per row.
        for i in start..end {
            toasty::create!(Protocol {
                created_at: 1,
                id: ProtocolId::new(i as i64),
                sig: i as i64,
                proto_kind: ProtocolKind::Vless,
                transport: Transport {
                    r#type: TransportType::Tcp
                },
                security: Security {
                    r#type: SecurityType::Reality,
                    sni: Some(format!("c{}.example.com", i % 1000)),
                    fp: None,
                    insecure: Some(false),
                },
                config: Deferred::from(Json(vless_cfg(i, wide))),
            })
            .exec(&mut tx)
            .await
            .expect("protocol");
        }
        if with_links {
            toasty::sql::statement(format!("{LINK_COLS}{links}{LINK_CONFLICT}"))
                .exec(&mut tx)
                .await
                .expect("links");
        }
        tx.commit().await.expect("commit");
    }
}

/// A page reader on its own connection: the production page read reduced to its
/// second step (`load_page_rows` over an id sample).
struct ReaderArm {
    stop: Arc<AtomicBool>,
    latencies: Arc<tokio::sync::Mutex<Vec<Duration>>>,
    handle: tokio::task::JoinHandle<()>,
}

fn spawn_reader(db: Arc<Database>, ids: Vec<EndpointId>) -> ReaderArm {
    let stop = Arc::new(AtomicBool::new(false));
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (s, lat) = (Arc::clone(&stop), Arc::clone(&latencies));
    let handle = tokio::spawn(async move {
        while !s.load(Ordering::Relaxed) {
            let t = Instant::now();
            let rows = db.load_page_rows(&ids, false).await;
            let dt = t.elapsed();
            if rows.is_ok() {
                lat.lock().await.push(dt);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    ReaderArm {
        stop,
        latencies,
        handle,
    }
}

impl ReaderArm {
    async fn finish(self) -> Vec<Duration> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.abort();
        let mut lats = self.latencies.lock().await.clone();
        lats.sort_unstable();
        lats
    }
}

fn sample_ids(n: usize) -> Vec<EndpointId> {
    (1..=n).map(|i| EndpointId::new(i as i64)).collect()
}

/// Quiet baseline: five page reads with no writer running.
async fn quiet_reads(db: &Database) -> Vec<Duration> {
    let ids = sample_ids(20);
    let mut lats = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        db.load_page_rows(&ids, false).await.expect("read");
        lats.push(t.elapsed());
    }
    lats.sort_unstable();
    lats
}

/// Import 20k MORE rows over a 40k preseed, with a page reader running beside
/// it; the preseed's quiet read is the baseline the burst is judged against.
async fn arm_import(mvcc: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), mvcc).await;
    import_burst(&db, 1, 40_000, true, true).await;
    let quiet = quiet_reads(&db).await;

    let reader = spawn_reader(Arc::clone(&db), sample_ids(20));
    let (cpu0, rss0) = (cpu_ms(), vmhwm_kb());
    let t0 = Instant::now();
    import_burst(&db, 40_001, 60_001, true, true).await;
    let wall = t0.elapsed();
    let cpu = cpu_ms() - cpu0;
    let rss = vmhwm_kb();
    let lats = reader.finish().await;
    let (db_b, wal_b, log_b) = disk(&path);
    println!(
        "IMPORT  mvcc={mvcc:<5} +20k rows: wall={wall:>7.2?} cpu={cpu:>6}ms ({:.0}% core) \
         peakRSS={:>4}MiB (+{}) disk: db={:>6}KiB wal={:>6}KiB log={:>6}KiB",
        cpu as f64 * 100.0 / wall.as_millis().max(1) as f64,
        mib(rss),
        i64::try_from(rss).unwrap_or(0) - i64::try_from(rss0).unwrap_or(0),
        db_b / 1024,
        wal_b / 1024,
        log_b / 1024
    );
    println!(
        "        reads(20 ids): quiet p50={:>7.2?}  during: n={:<4} p50={:>7.2?} p95={:>7.2?} max={:>7.2?}",
        pct(&quiet, 0.5),
        lats.len(),
        pct(&lats, 0.5),
        pct(&lats, 0.95),
        pct(&lats, 1.0)
    );
    drop(db);
}

/// The write-behind flush shape: one upsert per transaction through the app's
/// `retry_on_busy(_, 5)`, 500 times, with a reader beside it.
async fn arm_single_row(mvcc: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), mvcc).await;
    import_burst(&db, 1, 5_000, true, true).await;
    let quiet = quiet_reads(&db).await;

    let reader = spawn_reader(Arc::clone(&db), sample_ids(20));
    let (cpu0, rss0) = (cpu_ms(), vmhwm_kb());
    let t0 = Instant::now();
    let mut fails = 0usize;
    for i in 1..=500usize {
        let sql = format!("{LINK_COLS}{}{LINK_CONFLICT}", link_tuple(i));
        let handle = Arc::clone(&db);
        let r = leas_db::retry_on_busy(
            || async {
                let mut conn = handle.connection().await?;
                let mut tx = conn.transaction().await?;
                toasty::sql::statement(sql.clone()).exec(&mut tx).await?;
                tx.commit().await?;
                Ok(())
            },
            5,
        )
        .await;
        if r.is_err() {
            fails += 1;
        }
    }
    let wall = t0.elapsed();
    let cpu = cpu_ms() - cpu0;
    let rss = vmhwm_kb();
    let lats = reader.finish().await;
    let (db_b, wal_b, log_b) = disk(&path);
    println!(
        "SINGLE  mvcc={mvcc:<5} 500 one-row txns: wall={wall:>7.2?} cpu={cpu:>6}ms \
         peakRSS={:>4}MiB (+{}) disk: db={:>6}KiB wal={:>6}KiB log={:>6}KiB fails={fails}",
        mib(rss),
        i64::try_from(rss).unwrap_or(0) - i64::try_from(rss0).unwrap_or(0),
        db_b / 1024,
        wal_b / 1024,
        log_b / 1024
    );
    println!(
        "        reads: quiet p50={:>7.2?}  during: n={:<3} p50={:>7.2?} p95={:>7.2?} max={:>7.2?}",
        pct(&quiet, 0.5),
        lats.len(),
        pct(&lats, 0.5),
        pct(&lats, 0.95),
        pct(&lats, 1.0)
    );
}

/// The orphan-protocol anti-join at FEED scale: 5 % of protocols have no link.
/// Times the toasty `NOT IN` shape, the `NOT EXISTS` rewrite, and the `DELETE`.
async fn arm_purge(mvcc: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), mvcc).await;
    let linked = FEED * 95 / 100;
    import_burst(&db, 1, linked, true, true).await;
    import_burst(&db, linked, FEED, false, true).await;
    let (db_b, wal_b, log_b) = disk(&path);
    let mut out = format!(
        "PURGE   mvcc={mvcc:<5} protocols={FEED} orphans={} disk: db={}KiB wal={}KiB log={}KiB",
        FEED - linked,
        db_b / 1024,
        wal_b / 1024,
        log_b / 1024
    );
    let (not_in, not_exists) = time_antijoins(&db).await;
    let _ = write!(out, " not_in={not_in:.2?} not_exists={not_exists:.2?}");
    {
        let mut conn = db.connection().await.expect("conn");
        let t = Instant::now();
        toasty::sql::statement(
            "DELETE FROM protocols WHERE NOT EXISTS \
             (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id)",
        )
        .exec(&mut conn)
        .await
        .expect("delete");
        let _ = write!(out, " delete={:.2?}", t.elapsed());
    }
    println!("{out}");
}

/// The two anti-join shapes the orphan purge can use, timed one after the other
/// on the same connection pool.
async fn time_antijoins(db: &Database) -> (Duration, Duration) {
    let mut out = (Duration::ZERO, Duration::ZERO);
    for (slot, sql) in [
        (
            &mut out.0,
            "SELECT count(*) FROM protocols WHERE NOT (id IN (SELECT protocol_id FROM profile_stats))",
        ),
        (
            &mut out.1,
            "SELECT count(*) FROM protocols WHERE NOT EXISTS \
             (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id)",
        ),
    ] {
        let mut conn = db.connection().await.expect("conn");
        let t = Instant::now();
        let rows = toasty::sql::query(sql).exec(&mut conn).await.expect("q");
        assert_eq!(rows.len(), 1, "count query returns one row");
        *slot = t.elapsed();
    }
    out
}

/// What `protocols.config`'s WIDTH costs the anti-join: two identical 74k feeds,
/// one with a realistic config and one with the bare object a
/// `protocols`/`protocol_config` split would leave in the scanned table.
async fn arm_width(wide: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), false).await;
    let linked = FEED * 95 / 100;
    import_burst(&db, 1, linked, true, wide).await;
    import_burst(&db, linked, FEED, false, wide).await;
    let (not_in, not_exists) = time_antijoins(&db).await;
    let (db_b, _, _) = disk(&path);
    println!(
        "WIDTH   config={:<6} protocols={FEED} table={:>5}KiB not_in={not_in:>8.2?} not_exists={not_exists:>8.2?}",
        if wide { "wide" } else { "narrow" },
        db_b / 1024
    );
}

/// `upsert_protocols_bulk` is ONE typed upsert per protocol; every other
/// import family is a 400-row literal statement. What does that shape cost?
async fn arm_protocol_shape(chunked: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let t0 = Instant::now();
    let mut conn = db.connection().await.expect("conn");
    for start in (1..=PROTO_ROWS).step_by(BATCH) {
        let end = (start + BATCH).min(PROTO_ROWS + 1);
        let mut tx = conn.transaction().await.expect("tx");
        if chunked {
            let mut sql = String::from(
                "INSERT INTO protocols (id, sig, proto_kind, transport_type, security_type, \
                 security_sni, security_fp, security_insecure, config, created_at) VALUES ",
            );
            for i in start..end {
                if i > start {
                    sql.push(',');
                }
                let cfg = serde_json::to_string(&vless_cfg(i, true)).expect("json");
                let _ = write!(
                    sql,
                    "({i}, {i}, 'vless', 'tcp', 'reality', 'c{i}.example.com', NULL, 0, \
                     '{cfg}', 1)"
                );
            }
            toasty::sql::statement(sql)
                .exec(&mut tx)
                .await
                .expect("bulk");
        } else {
            for i in start..end {
                toasty::create!(Protocol {
                    created_at: 1,
                    id: ProtocolId::new(i as i64),
                    sig: i as i64,
                    proto_kind: ProtocolKind::Vless,
                    transport: Transport {
                        r#type: TransportType::Tcp
                    },
                    security: Security {
                        r#type: SecurityType::Reality,
                        sni: Some(format!("c{}.example.com", i % 1000)),
                        fp: None,
                        insecure: Some(false),
                    },
                    config: Deferred::from(Json(vless_cfg(i, true))),
                })
                .exec(&mut tx)
                .await
                .expect("protocol");
            }
        }
        tx.commit().await.expect("commit");
    }
    println!(
        "PROTOS  shape={:<8} rows={PROTO_ROWS} wall={:>7.2?}",
        if chunked { "chunk400" } else { "typed1" },
        t0.elapsed()
    );
}

/// The 0.9.0-pre.5 language surface this layer could use: the full window set
/// (`COMPAT.md` still claims `lag`/`lead`/`ntile` are missing) and
/// `WITH RECURSIVE`. Asserts, because a wrong answer here would silently
/// corrupt any query built on it.
#[tokio::test]
async fn window_functions_and_recursive_cte_answer_correctly() {
    let db = Database::in_memory().await.expect("db");
    let mut conn = db.connection().await.expect("conn");
    let rows = toasty::sql::query(
        "SELECT v, ntile(2) OVER (ORDER BY v) AS t, lag(v) OVER (ORDER BY v) AS prev          FROM (SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v)",
    )
    .exec(&mut conn)
    .await
    .expect("window query");
    assert_eq!(rows.len(), 3, "three window rows");
    let rec = toasty::sql::query(
        "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 5)          SELECT count(*) FROM c",
    )
    .exec(&mut conn)
    .await
    .expect("recursive cte");
    assert_eq!(rec.len(), 1, "one aggregate row");
    println!("WINDOW  ntile/lag over 3 rows + WITH RECURSIVE: ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn protocol_insert_shape() {
    for chunked in [false, true] {
        arm_protocol_shape(chunked).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn config_width_anti_join() {
    for wide in [true, false] {
        arm_width(wide).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn import_wal_vs_mvcc() {
    for mvcc in [false, true] {
        arm_import(mvcc).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn single_row_wal_vs_mvcc() {
    for mvcc in [false, true] {
        arm_single_row(mvcc).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn purge_wal_vs_mvcc() {
    for mvcc in [false, true] {
        arm_purge(mvcc).await;
    }
}
