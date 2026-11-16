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

/// The allocator the binary ships (default options — the app's
/// `configure()` retention tuning is its own axis). `--features lab-mimalloc`.
#[cfg(feature = "lab-mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
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

/// Current resident set size in KiB (`VmRSS`) — the per-arm delta uses this,
/// because `VmHWM` is a process-wide high-water mark that never falls.
fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("VmRSS")
}

const fn alloc_name() -> &'static str {
    if cfg!(feature = "lab-mimalloc") {
        "mimalloc"
    } else {
        "system"
    }
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
    let (cpu0, rss0) = (cpu_ms(), rss_kb());
    let t0 = Instant::now();
    import_burst(&db, 40_001, 60_001, true, true).await;
    let wall = t0.elapsed();
    let cpu = cpu_ms() - cpu0;
    let rss = vmhwm_kb();
    let lats = reader.finish().await;
    let (db_b, wal_b, log_b) = disk(&path);
    println!(
        "IMPORT  mvcc={mvcc:<5} alloc={:<8} +20k rows: wall={wall:>7.2?} cpu={cpu:>6}ms \
         ({:.0}% core) peakRSS={:>4}MiB (rss delta +{}KiB) disk: db={:>6}KiB wal={:>6}KiB \
         log={:>6}KiB",
        alloc_name(),
        cpu as f64 * 100.0 / wall.as_millis().max(1) as f64,
        mib(rss),
        i64::try_from(rss_kb()).unwrap_or(0) - i64::try_from(rss0).unwrap_or(0),
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
    let (cpu0, rss0) = (cpu_ms(), rss_kb());
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

/// Reader contention with the writer on its OWN OS thread and its OWN runtime,
/// so a slow statement in one cannot hide the other behind a shared worker: the
/// writer imports on a `std::thread`, the reader polls a ONE-id page every 5 ms
/// on the test runtime, and the reported quantity is p99 over the quiet p50.
async fn arm_contention(mvcc: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), mvcc).await;
    import_burst(&db, 1, 20_000, true, true).await;

    // Quiet baseline: 200 point reads, no writer.
    let one = vec![EndpointId::new(1)];
    let mut quiet = Vec::with_capacity(200);
    for _ in 0..200 {
        let t = Instant::now();
        db.load_page_rows(&one, false).await.expect("read");
        quiet.push(t.elapsed());
    }
    quiet.sort_unstable();

    let writer_db = Arc::clone(&db);
    let writer = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("writer runtime");
        rt.block_on(import_burst(&writer_db, 20_001, 40_001, true, true));
    });

    let mut during = Vec::with_capacity(1024);
    while !writer.is_finished() {
        let t = Instant::now();
        db.load_page_rows(&one, false).await.expect("read");
        during.push(t.elapsed());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    writer.join().expect("writer thread");
    during.sort_unstable();

    let (db_b, wal_b, log_b) = disk(&path);
    println!(
        "CONTEND mvcc={mvcc:<5} alloc={:<8} writer=20k rows reads: quiet n=200 p50={:>7.2?} \
         p99={:>7.2?}  during n={:<4} p50={:>7.2?} p95={:>7.2?} p99={:>7.2?} max={:>7.2?}  \
         stall p99/quiet-p50={:.1}x disk: db={}KiB wal={}KiB log={}KiB",
        alloc_name(),
        pct(&quiet, 0.50),
        pct(&quiet, 0.99),
        during.len(),
        pct(&during, 0.50),
        pct(&during, 0.95),
        pct(&during, 0.99),
        pct(&during, 1.0),
        pct(&during, 0.99).as_secs_f64() / pct(&quiet, 0.50).as_secs_f64(),
        db_b / 1024,
        wal_b / 1024,
        log_b / 1024
    );
}

/// `endpoint_rank::write` costs TWO statements per 400-row chunk: the
/// `INSERT OR REPLACE` (which nulls the raw `band` column) and a follow-up
/// `UPDATE … SET band = CASE …`. Since `band` derives from values this writer
/// already holds, it can ride the INSERT. Measure both shapes over a real
/// `endpoint_rank` table with its two indexes in place.
async fn arm_rank_write_shape(inline_band: bool) {
    const ROWS: usize = 5_000;
    const CHUNK: usize = 400;
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    let t0 = Instant::now();
    let threshold = 1_700_000_000i64;
    for chunk_start in (1..=ROWS).step_by(CHUNK) {
        let end = (chunk_start + CHUNK).min(ROWS + 1);
        let mut values = String::with_capacity((end - chunk_start) * 80);
        let mut ids = String::with_capacity((end - chunk_start) * 8);
        for i in chunk_start..end {
            if i > chunk_start {
                values.push(',');
                ids.push(',');
            }
            let newest = if i % 3 == 0 {
                threshold - 10
            } else {
                threshold + 10
            };
            let alive = i32::from(i % 5 != 0);
            let band = match (newest < threshold, alive) {
                (true, _) => 2,
                (false, 1) => 0,
                (false, _) => 1,
            };
            if inline_band {
                let _ = write!(
                    values,
                    "({i}, {}, {}, 0, x'0000000000000000', 'd{i}.example', '', x'04', {newest}, {alive}, {band})",
                    i % 5,
                    i % 3
                );
            } else {
                let _ = write!(
                    values,
                    "({i}, {}, {}, 0, x'0000000000000000', 'd{i}.example', '', x'04', {newest}, {alive})",
                    i % 5,
                    i % 3
                );
                let _ = write!(ids, "{i}");
            }
        }
        let columns = "endpoint_id, rank_bin, rank_stab, rank_proven, rank_weight, \
                       rank_domain, rank_sub_domain, rank_addr, rank_newest_seen, rank_alive";
        let sql = if inline_band {
            format!("INSERT OR REPLACE INTO endpoint_rank ({columns}, band) VALUES {values}")
        } else {
            format!("INSERT OR REPLACE INTO endpoint_rank ({columns}) VALUES {values}")
        };
        toasty::sql::statement(sql)
            .exec(&mut conn)
            .await
            .expect("insert");
        if !inline_band {
            toasty::sql::statement(format!(
                "UPDATE endpoint_rank SET band = CASE WHEN rank_newest_seen < {threshold} THEN 2 \
                 WHEN rank_alive = 1 THEN 0 ELSE 1 END WHERE endpoint_id IN ({ids})"
            ))
            .exec(&mut conn)
            .await
            .expect("band");
        }
    }
    println!(
        "RANK    shape={:<11} rows={ROWS} wall={:>7.2?}",
        if inline_band {
            "band-inline"
        } else {
            "two-stmt"
        },
        t0.elapsed()
    );
}

/// `PRAGMA wal_autocheckpoint` did not exist in 0.8.x (the 2026-09-16 claim
/// study marked it REJECTED-IMPOSSIBLE); 0.9.0-pre.5 lists it as supported.
/// Does tuning it change an import's WAL footprint or wall time?
async fn arm_wal_autocheckpoint(pages: Option<i64>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lab.db");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    let note = if let Some(pages) = pages {
        toasty::sql::statement(format!("PRAGMA wal_autocheckpoint = {pages}"))
            .exec(&mut conn)
            .await
            .expect("pragma");
        let rows = toasty::sql::query("PRAGMA wal_autocheckpoint")
            .exec(&mut conn)
            .await
            .expect("readback");
        format!("set={pages} readback={rows:?}")
    } else {
        String::from("default")
    };
    drop(conn);
    let t0 = Instant::now();
    import_burst(&db, 1, 20_000, true, true).await;
    let wall = t0.elapsed();
    let (db_b, wal_b, log_b) = disk(&path);
    println!(
        "WAL     autocheckpoint {note}: +20k rows wall={wall:>7.2?} db={}KiB wal={}KiB log={}KiB",
        db_b / 1024,
        wal_b / 1024,
        log_b / 1024
    );
}

/// `backfill_all` (open-time heal) reads every address row twice: once for the
/// min key per endpoint and once just to test membership. One grouped statement
/// can answer both. 74k endpoints, ~1.5 addresses each.
async fn arm_addr_scan_shape(group_by: bool) {
    const ENDPOINTS: usize = 74_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    for start in (1..=ENDPOINTS).step_by(BATCH) {
        let end = (start + BATCH).min(ENDPOINTS + 1);
        let mut values = String::new();
        for i in start..end {
            for add in 0..2 {
                if !values.is_empty() {
                    values.push(',');
                }
                let _ = write!(values, "({i}, x'04{:08x}', NULL)", (i * 2 + add) as u32);
            }
        }
        toasty::sql::statement(format!(
            "INSERT INTO endpoint_ip (endpoint_id, ip_key, country) VALUES {values} \
             ON CONFLICT(endpoint_id, ip_key) DO NOTHING"
        ))
        .exec(&mut conn)
        .await
        .expect("seed addresses");
    }
    let t0 = Instant::now();
    let rows = if group_by {
        toasty::sql::query("SELECT endpoint_id, min(ip_key) FROM endpoint_ip GROUP BY endpoint_id")
            .exec(&mut conn)
            .await
            .expect("grouped")
    } else {
        // The old pair of scans: the ordered first-wins read, then DISTINCT.
        let a = toasty::sql::query(
            "SELECT endpoint_id, ip_key FROM endpoint_ip ORDER BY endpoint_id, ip_key",
        )
        .exec(&mut conn)
        .await
        .expect("ordered");
        let b = toasty::sql::query("SELECT DISTINCT endpoint_id FROM endpoint_ip")
            .exec(&mut conn)
            .await
            .expect("distinct");
        a.into_iter().chain(b).collect::<Vec<_>>()
    };
    println!(
        "ADDR    shape={:<9} endpoints={ENDPOINTS} address_rows={} rows_returned={} wall={:>8.2?}",
        if group_by { "group_by" } else { "two_scans" },
        ENDPOINTS * 2,
        rows.len(),
        t0.elapsed()
    );
}

/// The orphan purge runs INSIDE the merge transaction, after that pair's
/// deletes, not in autocommit: does the anti-join hold its cost there?
async fn arm_purge_in_tx() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let linked = FEED * 95 / 100;
    import_burst(&db, 1, linked, true, true).await;
    import_burst(&db, linked, FEED, false, true).await;
    let mut conn = db.connection().await.expect("conn");
    let mut tx = conn.transaction().await.expect("tx");
    // The merge shape: delete this pair's links first, then purge.
    toasty::sql::statement("DELETE FROM profile_stats WHERE endpoint_id IN (1, 2)")
        .exec(&mut tx)
        .await
        .expect("pair delete");
    let t0 = Instant::now();
    toasty::sql::statement(
        "DELETE FROM protocols WHERE NOT EXISTS \
         (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id)",
    )
    .exec(&mut tx)
    .await
    .expect("purge");
    let purge = t0.elapsed();
    tx.commit().await.expect("commit");
    println!(
        "PURGE   in_tx=true protocols={FEED} orphans={} wall={purge:>8.2?}",
        FEED - linked + 2
    );
}

/// What the materialized ordering buys: the page's ORDER BY is index-served
/// today; an ordering whose first term no index carries (or the same order as a
/// window) pays a sorter over the whole table.
async fn arm_order_cost(shape: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    import_burst(&db, 1, FEED, true, true).await;
    // Rank rows for the feed, so the ordered read has the real row count.
    let mut conn = db.connection().await.expect("conn");
    for start in (1..=FEED).step_by(BATCH) {
        let end = (start + BATCH).min(FEED + 1);
        let mut values = String::new();
        for i in start..end {
            if !values.is_empty() {
                values.push(',');
            }
            let _ = write!(
                values,
                "({i}, {}, {}, 0, x'0000000000000000', 'd{i}.example', '', x'04', 1, 1, 0)",
                i % 5,
                i % 3
            );
        }
        toasty::sql::statement(format!(
            "INSERT OR REPLACE INTO endpoint_rank (endpoint_id, rank_bin, rank_stab, rank_proven, \
             rank_weight, rank_domain, rank_sub_domain, rank_addr, rank_newest_seen, rank_alive, \
             band) VALUES {values}"
        ))
        .exec(&mut conn)
        .await
        .expect("seed ranks");
    }
    let sql = match shape {
        // The shipped page shape: the covering index serves the order.
        "index" => {
            "SELECT endpoint_id FROM endpoint_rank WHERE band = 0 \
                    ORDER BY rank_bin, rank_stab, rank_weight DESC, rank_domain, \
                    rank_sub_domain, rank_addr, endpoint_id LIMIT 200"
        }
        // Same rows, an order no index carries: a sorter over the table.
        "sorter" => {
            "SELECT endpoint_id FROM endpoint_rank WHERE band = 0 \
                     ORDER BY rank_stab, rank_bin, rank_weight DESC, rank_domain, \
                     rank_sub_domain, rank_addr, endpoint_id LIMIT 200"
        }
        // The window form the audit asked about: number every row, then take 200.
        _ => {
            "SELECT endpoint_id FROM (SELECT endpoint_id, ROW_NUMBER() OVER \
              (ORDER BY rank_stab, rank_bin, rank_weight DESC, rank_domain, \
              rank_sub_domain, rank_addr) AS rn FROM endpoint_rank WHERE band = 0) \
              WHERE rn <= 200"
        }
    };
    let t0 = Instant::now();
    let rows = toasty::sql::query(sql)
        .exec(&mut conn)
        .await
        .expect("order");
    println!(
        "ORDER   shape={shape:<7} rows={FEED} returned={} wall={:>8.2?}",
        rows.len(),
        t0.elapsed()
    );
}

/// `Database::conn()` issues TWO pragmas on EVERY pooled connection: what do
/// they cost, per call, against the work a call does?
async fn arm_conn_setup(n_pragmas: usize) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    let t0 = Instant::now();
    for _ in 0..500 {
        if n_pragmas >= 1 {
            toasty::sql::query("PRAGMA busy_timeout=5000")
                .exec(&mut conn)
                .await
                .expect("busy");
        }
        if n_pragmas >= 2 {
            toasty::sql::query("PRAGMA synchronous=NORMAL")
                .exec(&mut conn)
                .await
                .expect("sync");
        }
    }
    println!(
        "SETUP   pragmas_per_call={n_pragmas} calls=500 wall={:>8.2?} ({:.1}µs/call)",
        t0.elapsed(),
        t0.elapsed().as_secs_f64() * 1e6 / 500.0
    );
}

/// `endpoint_rank::prune` used to delete one row per statement; `delete_for`
/// style `IN (…)` chunking is the alternative. 2 000 ids, one transaction.
async fn arm_prune_shape(chunked: bool) {
    const IDS: usize = 2_000;
    const CHUNK: usize = 400;
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    let mut values = String::new();
    for i in 1..=IDS {
        if i > 1 {
            values.push(',');
        }
        let _ = write!(
            values,
            "({i}, 0, 0, 0, x'0000000000000000', 'd', '', x'04', 1, 1, 0)"
        );
    }
    toasty::sql::statement(format!(
        "INSERT INTO endpoint_rank (endpoint_id, rank_bin, rank_stab, rank_proven, rank_weight, \
         rank_domain, rank_sub_domain, rank_addr, rank_newest_seen, rank_alive, band) \
         VALUES {values}"
    ))
    .exec(&mut conn)
    .await
    .expect("seed ranks");
    let mut tx = conn.transaction().await.expect("tx");
    let t0 = Instant::now();
    if chunked {
        for start in (1..=IDS).step_by(CHUNK) {
            let end = (start + CHUNK).min(IDS + 1);
            let ids = (start..end)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            toasty::sql::statement(format!(
                "DELETE FROM endpoint_rank WHERE endpoint_id IN ({ids})"
            ))
            .exec(&mut tx)
            .await
            .expect("delete");
        }
    } else {
        for i in 1..=IDS {
            toasty::sql::statement(format!("DELETE FROM endpoint_rank WHERE endpoint_id = {i}"))
                .exec(&mut tx)
                .await
                .expect("delete");
        }
    }
    tx.commit().await.expect("commit");
    println!(
        "PRUNE   shape={:<8} ids={IDS} wall={:>7.2?}",
        if chunked { "chunk400" } else { "per-row" },
        t0.elapsed()
    );
}

/// `get_group_member_counts` loaded every membership row and counted in Rust;
/// `GROUP BY` counts in SQL. 20 000 memberships over 50 groups.
async fn arm_group_counts(group_by: bool) {
    const ROWS: usize = 20_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    for start in (1..=ROWS).step_by(BATCH) {
        let end = (start + BATCH).min(ROWS + 1);
        let mut values = String::new();
        for i in start..end {
            if i > start {
                values.push(',');
            }
            let _ = write!(values, "({i}, 'grp-{}', 1, 0)", i % 50);
        }
        toasty::sql::statement(format!(
            "INSERT INTO endpoint_groups (endpoint_id, group_id, last_seen_at, sort_order) \
             VALUES {values} ON CONFLICT(endpoint_id, group_id) DO NOTHING"
        ))
        .exec(&mut conn)
        .await
        .expect("seed groups");
    }
    let t0 = Instant::now();
    let sql = if group_by {
        "SELECT group_id, COUNT(*) FROM endpoint_groups GROUP BY group_id"
    } else {
        "SELECT endpoint_id, group_id, last_seen_at, sort_order FROM endpoint_groups"
    };
    let rows = toasty::sql::query(sql)
        .exec(&mut conn)
        .await
        .expect("counts");
    println!(
        "GROUPS  shape={:<8} memberships={ROWS} rows_returned={} wall={:>8.2?}",
        if group_by { "group_by" } else { "load_all" },
        rows.len(),
        t0.elapsed()
    );
}

/// What text does the typed writer store for the enum columns and the JSON
/// config? A hand-written bulk INSERT has to store exactly this.
#[tokio::test]
async fn protocol_column_encoding() {
    let db = Database::in_memory().await.expect("db");
    let mut conn = db.connection().await.expect("conn");
    toasty::create!(Protocol {
        created_at: 1,
        id: ProtocolId::new(7),
        sig: 7,
        proto_kind: ProtocolKind::Vless,
        transport: Transport {
            r#type: TransportType::Tcp
        },
        security: Security {
            r#type: SecurityType::Reality,
            sni: Some("a.example".to_string()),
            fp: None,
            insecure: Some(false),
        },
        config: Deferred::from(Json(vless_cfg(7, true))),
    })
    .exec(&mut conn)
    .await
    .expect("protocol");
    let rows = toasty::sql::query(
        "SELECT proto_kind, transport_type, security_type, security_sni, security_insecure, \
         typeof(security_insecure), config FROM protocols",
    )
    .exec(&mut conn)
    .await
    .expect("read");
    println!("ENCODE  {rows:?}");
}

/// Is `index_profile_stats_by_last_seen_at` earning its write cost? Prints the
/// plans the purge and staleness queries get, then times a 20k-row link upsert
/// with the index present and after `DROP INDEX`.
async fn arm_index_audit(drop_index: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    import_burst(&db, 1, 20_000, true, true).await;
    let mut conn = db.connection().await.expect("conn");
    if drop_index {
        toasty::sql::statement("DROP INDEX IF EXISTS index_profile_stats_by_last_seen_at")
            .exec(&mut conn)
            .await
            .expect("drop index");
    }
    let plans = [
        (
            "purge_candidates",
            "SELECT e.id FROM endpoints e WHERE NOT EXISTS (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id AND p.last_seen_at >= 1)",
        ),
        (
            "stale_links",
            "SELECT ps.endpoint_id FROM profile_stats ps WHERE ps.last_seen_at < 1",
        ),
    ];
    for (label, sql) in plans {
        let rows = toasty::sql::query(format!("EXPLAIN QUERY PLAN {sql}"))
            .exec(&mut conn)
            .await
            .expect("plan");
        println!("PLAN    index_dropped={drop_index} {label} rows={rows:?}");
    }
    drop(conn);
    // 20k MORE rows through the same writers: the upsert path plus the index
    // maintenance the arm is asking about, on ids that cannot conflict.
    let t0 = Instant::now();
    import_burst(&db, 20_001, 40_001, true, true).await;
    println!(
        "INDEX   last_seen_index={:<8} 20k link-upsert rerun wall={:>7.2?}",
        if drop_index { "dropped" } else { "present" },
        t0.elapsed()
    );
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
            let rows: Vec<Protocol> = (start..end)
                .map(|i| Protocol {
                    created_at: 0,
                    id: ProtocolId::new(i as i64),
                    sig: i as i64,
                    proto_kind: ProtocolKind::Vless,
                    transport: Transport {
                        r#type: TransportType::Tcp,
                    },
                    security: Security {
                        r#type: SecurityType::Reality,
                        sni: Some(format!("c{}.example.com", i % 1000)),
                        fp: None,
                        insecure: Some(false),
                    },
                    config: Deferred::from(Json(vless_cfg(i, true))),
                    links: Deferred::default(),
                })
                .collect();
            leas_db::upsert_protocols_bulk(&mut tx, &rows)
                .await
                .expect("bulk");
        } else {
            for i in start..end {
                Protocol::upsert_by_id(ProtocolId::new(i as i64))
                    .sig(i as i64)
                    .proto_kind(ProtocolKind::Vless)
                    .transport(Transport {
                        r#type: TransportType::Tcp,
                    })
                    .security(Security {
                        r#type: SecurityType::Reality,
                        sni: Some(format!("c{}.example.com", i % 1000)),
                        fp: None,
                        insecure: Some(false),
                    })
                    .config(vless_cfg(i, true))
                    .on_create(|create| create.created_at(1))
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

/// The per-connection settings moved to the driver's pool hook must actually
/// REACH a pooled connection: `synchronous` 1 (`NORMAL`), `busy_timeout` 5000,
/// `foreign_keys` 1. A quoted-vs-bare pragma value, or a hook that runs before
/// the pool starts handing connections out, would leave the defaults.
#[tokio::test]
async fn pooled_connection_carries_the_driver_pragmas() {
    async fn int(conn: &mut toasty::Connection, sql: &str) -> i64 {
        let rows = toasty::sql::query(sql).exec(conn).await.expect("pragma");
        rows.into_iter()
            .find_map(|row| match row {
                toasty_core::stmt::Value::Record(r) => match r.fields.first() {
                    Some(toasty_core::stmt::Value::I64(v)) => Some(*v),
                    _ => None,
                },
                _ => None,
            })
            .expect("one row")
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let db = open(dir.path(), false).await;
    let mut conn = db.connection().await.expect("conn");
    let sync = int(&mut conn, "PRAGMA synchronous").await;
    let busy = int(&mut conn, "PRAGMA busy_timeout").await;
    let fk = int(&mut conn, "PRAGMA foreign_keys").await;
    println!("PRAGMAS synchronous={sync} busy_timeout={busy} foreign_keys={fk}");
    assert_eq!(sync, 1, "synchronous must be NORMAL (1)");
    assert_eq!(busy, 5000, "busy_timeout must be 5000 ms");
    assert_eq!(fk, 1, "foreign_keys must be ON");
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
async fn address_scan_and_order_shapes() {
    for group_by in [false, true] {
        arm_addr_scan_shape(group_by).await;
    }
    for shape in ["index", "sorter", "window"] {
        arm_order_cost(shape).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn purge_in_transaction() {
    arm_purge_in_tx().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn conn_setup_overhead() {
    for n in [0, 1, 2, 0, 1, 2] {
        arm_conn_setup(n).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn prune_and_group_count_shapes() {
    for chunked in [false, true, false, true] {
        arm_prune_shape(chunked).await;
    }
    for group_by in [false, true, false, true] {
        arm_group_counts(group_by).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn index_audit() {
    for drop_index in [false, true] {
        arm_index_audit(drop_index).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn rank_write_shape() {
    for inline in [false, true, false, true] {
        arm_rank_write_shape(inline).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "research lab; prints a table, asserts nothing"]
async fn wal_autocheckpoint_tuning() {
    for pages in [None, Some(100), Some(1000), Some(10_000)] {
        arm_wal_autocheckpoint(pages).await;
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
async fn reader_contention_wal_vs_mvcc() {
    for mvcc in [false, true] {
        arm_contention(mvcc).await;
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
