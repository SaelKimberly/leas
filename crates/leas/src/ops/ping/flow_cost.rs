//! Cost lab for the Fast + Real Ping flow (perf evidence, not a gate).
//!
//! Ignored by default. Run with:
//!
//! ```text
//! cargo test -p leas --release --lib -- --ignored --nocapture flow_cost
//! ```
//!
//! Every row is the MEDIAN of its per-operation samples on this machine (a
//! mean is unusable: the first sample of a section pays page-cache, statement
//! compilation and pool setup that steady state never pays).
//!
//! Allocation COUNTS are not available in-process: `turso` installs a
//! `#[global_allocator]` (its default `mimalloc` feature) and a second one is a
//! compile error, while `valgrind --tool=dhat` on the test binary dies with
//! SIGILL at startup under that same allocator. Allocation figures in the lab
//! report are therefore derived from the code path (one `String::clone` is one
//! allocation) and backed by A/B timing of the allocation-free variant.
//!
//! `LEAS_MEASURE_DB=/path/to/data.db` additionally measures the per-tick
//! profiles reload against a copy of a real feed (never the live file).
//!
//! `LEAS_SCALE=7686,50000,200000` (or `=1` for that default) additionally
//! runs the synthetic page-scale lab: seed a temp feed at each N, materialize
//! rank keys, and measure the Active page for the filesort sorts across
//! offsets, plus the band-seek A/B (P1b before/after). Independent of a real
//! feed file.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, dead_code)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use leas_config::IpProvider;
use leas_db::models::{Endpoint, EndpointRow, Latency, ProfileErr, ProfileStats, PurgatoryView};
use leas_db::profiles_query::{PageRequest, PageSort, PlanScope};
use leas_proto::proto_spec::ProtocolConfig;
use tokio::sync::mpsc;

use super::*;
use crate::ops::profiles::test_support::{fake_row, test_state};

// ── timing ─────────────────────────────────────────────────────────────────

/// Accumulates one sample per operation.
///
/// The report uses the MEDIAN, not the mean: the first call of an async section
/// pays one-off costs a steady-state batch never pays (page-cache fill on a
/// freshly opened database copy, statement compilation, pool creation), and
/// with a handful of samples a single cold one drags the mean by a factor — the
/// same page query read 12.4 ms cold against ~0.5 ms warm on consecutive runs.
/// A median is also what makes two runs comparable.
struct Acc {
    samples: Vec<u64>,
}

impl Acc {
    const fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn add(&mut self, elapsed: Duration) {
        self.samples
            .push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
    }

    /// Per-operation row, with `divisor` folding a batched op down to one item.
    fn row(&self, name: &str, divisor: f64) -> TableRow {
        let mut samples = self.samples.clone();
        samples.sort_unstable();
        let ns = match samples.len() {
            0 => 0.0,
            n if n % 2 == 1 => samples[n / 2] as f64,
            n => (samples[n / 2 - 1] as f64 + samples[n / 2] as f64) / 2.0,
        };
        TableRow {
            name: name.to_owned(),
            ns: ns / divisor,
            n: samples.len() as u32,
        }
    }
}

struct TableRow {
    name: String,
    ns: f64,
    n: u32,
}

fn print_table(title: &str, rows: &[TableRow]) {
    println!("\n== {title} ==");
    println!("{:<56} {:>14} {:>4}", "operation", "ns/op", "n");
    for row in rows {
        println!("{:<56} {:>14.1} {:>4}", row.name, row.ns, row.n);
    }
}

fn bench_sync(iters: u32, mut op: impl FnMut()) -> Acc {
    let mut acc = Acc::new();
    for _ in 0..3 {
        op();
    }
    for _ in 0..iters {
        let started = Instant::now();
        op();
        acc.add(started.elapsed());
    }
    acc
}

// ── synthetic feed ─────────────────────────────────────────────────────────

fn synth_rows(endpoints: usize, protos: usize) -> Vec<EndpointRow> {
    (1..=endpoints)
        .map(|i| {
            let host = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256);
            fake_row(i as i64, &host, protos)
        })
        .collect()
}

async fn seed_db(state: &crate::AppState, rows: &[EndpointRow]) {
    let mut conn = state.db.connection().await.expect("conn");
    let mut tx = conn.transaction().await.expect("tx");
    let endpoints: Vec<Endpoint> = rows.iter().map(|r| r.endpoint.clone()).collect();
    let protocols: Vec<leas_db::models::Protocol> = rows
        .iter()
        .flat_map(|r| r.protocols.values().cloned())
        .collect();
    let links: Vec<ProfileStats> = rows.iter().flat_map(|r| r.links.iter().cloned()).collect();
    leas_db::upsert_endpoints_bulk(&mut tx, &endpoints)
        .await
        .expect("endpoints");
    leas_db::upsert_protocols_bulk(&mut tx, &protocols)
        .await
        .expect("protocols");
    leas_db::upsert_links_bulk(&mut tx, &links)
        .await
        .expect("links");
    tx.commit().await.expect("commit");
}

// ── stub probes ────────────────────────────────────────────────────────────

struct NullRunner;

impl BatchProbeRunner for NullRunner {
    fn fast<'a>(
        &'a self,
        _config_type: i32,
        _addr: &'a str,
        _port: u16,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
        Box::pin(async move {
            ProbeOutcome::Ok {
                latency_ms: Some(10),
                ip_info: None,
            }
        })
    }

    fn real<'a>(
        &'a self,
        _endpoint: &'a Endpoint,
        _addresses: &'a [std::net::IpAddr],
        _config: &'a ProtocolConfig,
        _req: NativeProbeReq<'a>,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
        Box::pin(async move {
            ProbeOutcome::Ok {
                latency_ms: Some(50),
                ip_info: Some("1.2.3.4".to_owned()),
            }
        })
    }
}

fn batch_params(
    state: &crate::AppState,
    tx: mpsc::Sender<CoreEvent>,
    plan: Vec<PlanLink>,
    real_phase: bool,
    page_size: usize,
    runner: Arc<dyn BatchProbeRunner>,
) -> BatchParams {
    BatchParams {
        scheduler: state.scheduler.clone(),
        db: state.db.clone(),
        writer: state.link_stage.clone(),
        tx,
        runner,
        stop: state.speed_test_stop.clone(),
        meters: Arc::new(crate::types::BatchMeters::default()),
        plan: PlanSource::Links(plan),
        real_phase,
        dedup_endpoints: false,
        fast_timeout: Duration::from_secs(2),
        real_timeout: Duration::from_secs(2),
        real_retries: 1,
        ping_url: "http://127.0.0.1/".to_owned(),
        ip_provider: IpProvider::IpApi,
        defer_delay: Duration::from_millis(50),
        real_concurrency: 64,
        fast_concurrency: 64,
        page_size,
        error_ttl_hours: None,
        dns_cache_ttl_secs: 86400,
        batch_slot: Arc::new(OnceLock::new()),
    }
}

// ── the report ─────────────────────────────────────────────────────────────

#[ignore = "perf lab: run explicitly with --ignored"]
#[test]
fn flow_cost_sizes() {
    use std::mem::size_of;
    println!("\n== sizes (bytes) ==");
    for (name, size) in [
        ("ProfileStats", size_of::<ProfileStats>()),
        ("Endpoint", size_of::<Endpoint>()),
        ("Protocol (db row)", size_of::<leas_db::models::Protocol>()),
        ("EndpointRow", size_of::<EndpointRow>()),
        ("PlanLink", size_of::<PlanLink>()),
        ("CoreEvent", size_of::<crate::types::CoreEvent>()),
        ("Latency", size_of::<Latency>()),
        ("ErrorInfo", size_of::<leas_db::models::ErrorInfo>()),
        ("ProbeOutcome", size_of::<ProbeOutcome>()),
        ("ProtocolConfig", size_of::<ProtocolConfig>()),
        ("LinkPatch", size_of::<leas_db::LinkPatch>()),
    ] {
        println!("{name:<56} {size:>6}");
    }
}

#[ignore = "perf lab: run explicitly with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_cost_report() {
    let mut rows_out: Vec<TableRow> = Vec::new();

    // ── 1. plan construction ───────────────────────────────────────────
    let page = synth_rows(200, 4);
    let links_all: Vec<ProfileStats> = page.iter().flat_map(|r| r.links.iter().cloned()).collect();
    let plan_acc = bench_sync(200, || {
        let plan: Vec<PlanLink> = page.iter().flat_map(plan_row_links).collect();
        black_box(plan.len());
    });
    rows_out.push(plan_acc.row("plan_row_links (per link)", 800.0));

    // ── 2. write-behind stage / patch build / window write ──────────────
    let state = test_state(page.clone()).await;
    seed_db(&state, &page).await;
    let make_staged = |i: usize| {
        let mut link = links_all[i % links_all.len()].clone();
        link.latency = Some(Latency::Fast { delay: 12 });
        link.error = Some(leas_db::models::ErrorInfo {
            kind: ProfileErr::Fast,
            text: "Connection refused by the remote proxy host".to_owned(),
        });
        link
    };
    // Pre-built, so the timed region contains the stage itself and not the
    // snapshot the caller already holds.
    let prebuilt: Vec<ProfileStats> = (0..512).map(make_staged).collect();

    let writer = state.link_stage.clone();
    let stage_acc = bench_sync(200_000, || {
        let link = &prebuilt[black_box(0)];
        writer.stage(link, leas_db::LinkGroups::RESULT);
    });
    rows_out.push(stage_acc.row("WriteBehind<LinkSpec>::stage (RESULT)", 1.0));
    writer.flush().await.expect("flush");

    let stage3_acc = bench_sync(100_000, || {
        let link = &prebuilt[black_box(1)];
        writer.stage(link, leas_db::LinkGroups::ALL);
    });
    rows_out.push(stage3_acc.row("WriteBehind<LinkSpec>::stage (ALL: 3 group inserts)", 1.0));
    writer.flush().await.expect("flush");

    let mut patch_acc = Acc::new();
    for _ in 0..64 {
        let links: Vec<ProfileStats> = (0..512).map(make_staged).collect();
        let started = Instant::now();
        let patches: Vec<leas_db::LinkPatch> = links
            .iter()
            .map(|link| leas_db::LinkPatch {
                link: link.clone(),
                groups: leas_db::LinkGroups::RESULT,
            })
            .collect();
        patch_acc.add(started.elapsed());
        black_box(patches.len());
    }
    rows_out.push(patch_acc.row("LinkPatch build (per patch)", 512.0));

    let mut flush_acc = Acc::new();
    for _ in 0..32 {
        for link in (0..512).map(make_staged) {
            writer.stage(&link, leas_db::LinkGroups::RESULT);
        }
        let started = Instant::now();
        writer.flush().await.expect("flush");
        flush_acc.add(started.elapsed());
    }
    rows_out.push(flush_acc.row("flush window (512 links, drain+write)", 512.0));

    let patches: Vec<leas_db::LinkPatch> = (0..512)
        .map(|i| leas_db::LinkPatch {
            link: make_staged(i),
            groups: leas_db::LinkGroups::RESULT,
        })
        .collect();
    let mut apply_acc = Acc::new();
    for _ in 0..32 {
        let started = Instant::now();
        state.db.apply_link_patches(&patches).await.expect("apply");
        apply_acc.add(started.elapsed());
    }
    rows_out.push(apply_acc.row("apply_link_patches (512 links, no drain)", 512.0));

    // ── 3. per-result staging through the batch's own path ─────────────
    let (tx, rx) = mpsc::channel::<CoreEvent>(1 << 16);
    let params = batch_params(&state, tx, Vec::new(), true, 200, Arc::new(NullRunner));
    let shared = Arc::new(BatchShared::new(params));
    let outcome_ok = ProbeOutcome::Ok {
        latency_ms: Some(37),
        ip_info: Some("1.2.3.4".to_owned()),
    };
    let outcome_err = ProbeOutcome::Failed {
        text: "connection timed out".to_owned(),
        class: ProbeClass::Timeout,
        hard: true,
        evidence: None,
    };
    let stage_result_acc = bench_sync(4096, || {
        let link = &links_all[black_box(0)];
        shared.stage_result(link, TestType::TcpPing, &outcome_ok);
        shared.stage_result(link, TestType::RealPing, &outcome_err);
    });
    rows_out.push(stage_result_acc.row("BatchShared::stage_result", 2.0));
    drop(rx);

    // ── 4. fast-probe dedup key ────────────────────────────────────────
    let host = "edge.example-subscription-domain.net".to_owned();
    let port = 443_u16;
    let mut string_map: HashMap<(String, u16), u8> = HashMap::new();
    string_map.insert((host.clone(), port), 1);
    let key_acc = bench_sync(200_000, || {
        let key = (host.clone(), port);
        black_box(string_map.get(&key));
    });
    rows_out.push(key_acc.row("dedup get, String key (clone + hash)", 1.0));

    let host_arc: Arc<str> = Arc::from(host.as_str());
    let mut arc_map: HashMap<(Arc<str>, u16), u8> = HashMap::new();
    arc_map.insert((host_arc.clone(), port), 1);
    let arc_acc = bench_sync(200_000, || {
        black_box(arc_map.get(&(host_arc.clone(), port)));
    });
    rows_out.push(arc_acc.row("dedup get, Arc<str> key (refcount bump)", 1.0));

    let mut hash_map: HashMap<(u64, u16), u8> = HashMap::new();
    hash_map.insert((fnv(host.as_bytes()), port), 1);
    let hash_acc = bench_sync(200_000, || {
        black_box(hash_map.get(&(fnv(host.as_bytes()), port)));
    });
    rows_out.push(hash_acc.row("dedup get, prehashed (u64, u16) key", 1.0));

    let outcome_map: HashMap<(String, u16), ProbeOutcome> = [((
        host.clone(),
        port,
        ProbeOutcome::Failed {
            text: "connection timed out after 5000 ms".to_owned(),
            class: ProbeClass::Timeout,
            hard: true,
            evidence: None,
        },
    ))]
    .into_iter()
    .fold(HashMap::new(), |mut m, (h, p, o)| {
        m.insert((h, p), o);
        m
    });
    let key = (host.clone(), port);
    let outcome_acc = bench_sync(200_000, || {
        black_box(outcome_map.get(&key).cloned());
    });
    rows_out.push(outcome_acc.row("dedup hit: ProbeOutcome::clone (failure)", 1.0));

    // ── 5. real-probe preparation ──────────────────────────────────────
    let protocol_id = links_all[0].protocol_id;
    let mut load_acc = Acc::new();
    for _ in 0..200 {
        let started = Instant::now();
        let loaded = load_protocol_with_config(&state.db, protocol_id)
            .await
            .expect("load")
            .expect("row");
        load_acc.add(started.elapsed());
        black_box(loaded);
    }
    rows_out.push(load_acc.row("load_protocol_with_config (per real probe)", 1.0));

    let loaded = load_protocol_with_config(&state.db, protocol_id)
        .await
        .expect("load")
        .expect("row");
    let clone_acc = bench_sync(20_000, || {
        let cfg: ProtocolConfig = loaded.config.get().0.clone();
        black_box(cfg);
    });
    rows_out.push(clone_acc.row("ProtocolConfig::clone", 1.0));

    // ── 6. scheduler transitions ───────────────────────────────────────
    let scheduler = crate::ops::scheduler::TaskScheduler::new(0, 0);
    let link = &links_all[0];
    let mut sched_acc = Acc::new();
    for _ in 0..20_000 {
        let started = Instant::now();
        let id = match scheduler.schedule(link, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("unexpected {other:?}"),
        };
        scheduler.complete(link, id, TaskKind::FastPing).await;
        sched_acc.add(started.elapsed());
    }
    rows_out.push(sched_acc.row("scheduler schedule+complete (round trip)", 1.0));

    // ── 7. UI per-result work: handler + live re-sort ──────────────────
    rows_out.extend(hit_miss_rows(true).await);
    rows_out.extend(hit_miss_rows(false).await);

    let mut sort_acc = Acc::new();
    let mut sort_row = page[0].clone();
    for _ in 0..50_000 {
        let started = Instant::now();
        sort_row.sort_links_by_test_priority(false);
        sort_row.select_best_measured_link();
        sort_acc.add(started.elapsed());
        black_box(sort_row.selected_protocol);
    }
    rows_out.push(sort_acc.row("sort_links_by_test_priority + select_best", 1.0));

    // ── 8. batch dispatch bookkeeping ──────────────────────────────────
    // The plan holds `Arc<Endpoint>`s, one per row, so the measurement uses a
    // real plan page rather than a row.
    let page_links: Vec<PlanLink> = page.iter().flat_map(plan_row_links).collect();
    let dispatch_acc = bench_sync(50_000, || {
        let plan = &page_links[black_box(0)];
        let key = (plan.link.protocol_id, plan.link.endpoint_id);
        let endpoint_map: DashMap<EndpointId, Arc<Endpoint>> = DashMap::new();
        endpoint_map
            .entry(plan.endpoint.id)
            .or_insert_with(|| Arc::clone(&plan.endpoint));
        let config_map: DashMap<(ProtocolId, EndpointId), i32> = DashMap::new();
        config_map.insert(key, 0);
        black_box((endpoint_map.len(), config_map.len()));
    });
    rows_out.push(dispatch_acc.row("dispatch_page maps per link (2 DashMaps+Arc)", 1.0));

    let probe_dash: DashMap<(ProtocolId, EndpointId), ProfileStats> = DashMap::new();
    // Give it a non-empty population so the shard walk is realistic.
    for link in links_all.iter().take(512) {
        probe_dash.insert((link.protocol_id, link.endpoint_id), link.clone());
    }
    let dash_len_acc = bench_sync(200_000, || {
        black_box(probe_dash.len());
    });
    rows_out.push(dash_len_acc.row("DashMap::len() (512-entry map)", 1.0));

    let insert_dash: DashMap<(ProtocolId, EndpointId), ProfileStats> = DashMap::new();
    insert_dash.insert(
        (links_all[0].protocol_id, links_all[0].endpoint_id),
        links_all[0].clone(),
    );
    let dash_insert_acc = bench_sync(200_000, || {
        insert_dash.insert(
            (links_all[0].protocol_id, links_all[0].endpoint_id),
            links_all[0].clone(),
        );
    });
    rows_out.push(dash_insert_acc.row("DashMap::insert (replace, 1-entry map)", 1.0));

    let rank_ids: Vec<EndpointId> = page.iter().map(|r| r.endpoint.id).collect();
    let mut rank_acc = Acc::new();
    for _ in 0..20 {
        let started = Instant::now();
        state
            .db
            .refresh_endpoint_ranks(&rank_ids)
            .await
            .expect("ranks");
        rank_acc.add(started.elapsed());
    }
    rows_out.push(rank_acc.row("refresh_endpoint_ranks (200 endpoints)", 200.0));

    let probe_hash: HashMap<(ProtocolId, EndpointId), ProfileStats> = probe_dash
        .iter()
        .map(|e| (*e.key(), e.value().clone()))
        .collect();
    let hash_len_acc = bench_sync(200_000, || {
        black_box(probe_hash.len());
    });
    rows_out.push(hash_len_acc.row("HashMap::len() (512-entry map)", 1.0));

    let page_clone = page.clone();
    let drop_acc = bench_sync(2000, || {
        let rows = page_clone.clone();
        let started_drop = std::time::Instant::now();
        drop(rows);
        black_box(started_drop.elapsed());
    });
    rows_out.push(drop_acc.row("clone+drop a 200-row page (per row)", 200.0));

    let endpoint_clone_acc = bench_sync(200_000, || {
        black_box(page[0].endpoint.clone());
    });
    rows_out.push(endpoint_clone_acc.row("Endpoint::clone (host String alloc)", 1.0));

    let link_clone_acc = bench_sync(200_000, || {
        black_box(links_all[0].clone());
    });
    rows_out.push(link_clone_acc.row("ProfileStats::clone (no error set)", 1.0));

    let mut err_link = links_all[0].clone();
    err_link.error = Some(leas_db::models::ErrorInfo {
        kind: ProfileErr::Real,
        text: "connection timed out after 5000 ms".to_owned(),
    });
    let err_clone_acc = bench_sync(200_000, || {
        black_box(err_link.clone());
    });
    rows_out.push(err_clone_acc.row("ProfileStats::clone (error text set)", 1.0));

    // fast dedup owner path: key clone + lock + cache insert + in-flight remove
    let mut dedup_cache: HashMap<(String, u16), ProbeOutcome> = HashMap::new();
    let mut in_flight: HashMap<(String, u16), Arc<tokio::sync::Notify>> = HashMap::new();
    let dedup_key = (host.clone(), port);
    let dedup_acc = bench_sync(20_000, || {
        let key = (host.clone(), port);
        let notify = Arc::new(tokio::sync::Notify::new());
        in_flight.insert(key.clone(), notify.clone());
        dedup_cache.insert(
            key.clone(),
            ProbeOutcome::Ok {
                latency_ms: Some(9),
                ip_info: None,
            },
        );
        in_flight.remove(&dedup_key);
        black_box(dedup_cache.len() + in_flight.len());
    });
    rows_out.push(dedup_acc.row("fast dedup owner: 2 key clones + 2 map ops", 1.0));

    // ── 9. connection acquisition (finish_batch opens one after the burst) ─
    let mut acquires: Vec<u128> = Vec::with_capacity(20);
    for _ in 0..20 {
        let started = Instant::now();
        let conn = state.db.connection().await.expect("conn");
        acquires.push(started.elapsed().as_micros());
        drop(conn);
    }
    println!("[pool] db.connection() acquisitions (us): {acquires:?}");
    let mut sorted = acquires.clone();
    sorted.sort_unstable();
    rows_out.push(TableRow {
        name: "db.connection() acquisition (median)".to_owned(),
        ns: sorted[sorted.len() / 2] as f64 * 1000.0,
        n: 20,
    });

    // ── 10. batch-end checkpoint (finish_batch runs one per batch) ──────
    let mut ckpt_acc = Acc::new();
    for _ in 0..20 {
        let Ok(mut conn) = state.db.connection().await else {
            continue;
        };
        let started = Instant::now();
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            toasty::sql::query("PRAGMA wal_checkpoint(PASSIVE)").exec(&mut conn),
        )
        .await;
        ckpt_acc.add(started.elapsed());
    }
    rows_out.push(ckpt_acc.row("finish_batch: wal_checkpoint(PASSIVE), in-memory db", 1.0));

    // ── 10. end-to-end pipeline (stub probes, no sockets) ──────────────
    // Each variant runs TWICE: the first `run_batch` of a process is the one
    // that shows the ~1.5 ms/link tail (3.1 s over 2,000 links, against 53–59
    // µs/link for every later run), so the second pass is the steady-state
    // number and the pair is itself the evidence.
    for real_phase in [false, true] {
        for pass in 0..2 {
            let feed = synth_rows(500, 4);
            let state = test_state(feed.clone()).await;
            seed_db(&state, &feed).await;
            let plan: Vec<PlanLink> = feed.iter().flat_map(plan_row_links).collect();
            let planned = plan.len();
            let (tx, rx) = mpsc::channel::<CoreEvent>(1 << 16);
            let params = batch_params(&state, tx, plan, real_phase, 500, Arc::new(NullRunner));
            // The batch publishes its shared state here at start: after the run it
            // carries the level spans, the wall time and the flush count, which is
            // what says whether the tail sits in the probes or in `finish_batch`.
            let slot = Arc::clone(&params.batch_slot);
            let started = Instant::now();
            run_batch(params).await;
            let elapsed = started.elapsed();
            drop(rx);
            if let Some(shared) = slot.get() {
                println!("[summary] {}", summary_line(shared));
            }
            let label = if real_phase { "fast+real" } else { "fast only" };
            let pass_label = if pass == 0 { "pass 1" } else { "pass 2" };
            println!(
                "[end-to-end] {label} ({pass_label}): {planned} links in {:.1} ms ({:.1} us/link)",
                elapsed.as_secs_f64() * 1000.0,
                elapsed.as_secs_f64() * 1e6 / planned as f64
            );
            rows_out.push(TableRow {
                name: format!("run_batch {label} ({pass_label}, per link)"),
                ns: elapsed.as_nanos() as f64 / planned as f64,
                n: 1,
            });
        }
    }

    // ── 11. batch end in isolation (the e2e tail's suspect) ────────────
    // The end-to-end rows show a reproducible ~3.09 s stall on the SECOND
    // batch of each kind; `finish_batch` is the only code on that path with
    // multi-second bounds (2 s `db.connection()`, 2 s checkpoint). This times
    // it alone, with a staged window to flush.
    let end_state = test_state(synth_rows(500, 4)).await;
    seed_db(&end_state, &synth_rows(500, 4)).await;
    let (end_tx, end_rx) = mpsc::channel::<CoreEvent>(1 << 16);
    let end_shared = Arc::new(BatchShared::new(batch_params(
        &end_state,
        end_tx,
        Vec::new(),
        false,
        500,
        Arc::new(NullRunner),
    )));
    for link in &links_all {
        end_shared.stage_result(link, TestType::TcpPing, &outcome_ok);
    }
    let started = Instant::now();
    finish_batch(&end_shared).await;
    println!(
        "[batch end] finish_batch alone: {:.1} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    rows_out.push(TableRow {
        name: "finish_batch (flush + checkpoint + sweep)".to_owned(),
        ns: started.elapsed().as_nanos() as f64,
        n: 1,
    });
    drop(end_rx);

    // ── 12. real-feed page path (optional) ─────────────────────────────
    if let Ok(path) = std::env::var("LEAS_MEASURE_DB") {
        match leas_db::Database::open(&path).await {
            Ok(db) => {
                let db = Arc::new(db);
                let request = PageRequest {
                    view: PurgatoryView::All,
                    active_threshold: 0,
                    scope: PlanScope::All,
                    search: None,
                    group_id: None,
                    sort: PageSort::Port,
                    ascending: true,
                    offset: 0,
                    limit: PROFILES_PAGE_SIZE,
                };
                let mut page_acc = Acc::new();
                for _ in 0..10 {
                    let started = Instant::now();
                    let page = db.profiles_page(&request).await.expect("page");
                    page_acc.add(started.elapsed());
                    black_box(page.ids.len());
                }
                rows_out.push(page_acc.row("profiles_page (one page, real feed)", 1.0));

                // The Test sort across OFFSETS on the REAL feed. This is the
                // 2026-10-01 question: `profiles_page` p99 was 1,004.3 ms on a
                // 74,014-endpoint feed, four CONSECUTIVE slow statements (the
                // deep-offset page-walk shape), while the same window reported
                // p50 = 1.2 ms — a shape that is cheap and a tail that is not.
                // The synthetic `LEAS_SCALE` lab already sweeps
                // (Address|Port|Test) x {0, total/2, N-200}; this is the same
                // sweep against the real rows, which is what closes
                // `adr/0010:79`'s pending N in {50k, 200k} acceptance.
                let mut total = 0usize;
                for (view, vtag) in [
                    (PurgatoryView::All, "All"),
                    (PurgatoryView::Active, "Active"),
                ] {
                    for (sort, tag) in [(PageSort::Port, "Port"), (PageSort::Test, "Test")] {
                        let head = PageRequest {
                            view,
                            active_threshold: 0,
                            scope: PlanScope::All,
                            search: None,
                            group_id: None,
                            sort,
                            ascending: true,
                            offset: 0,
                            limit: 1,
                        };
                        total = db.profiles_page(&head).await.expect("count").total as usize;
                        if total == 0 {
                            continue;
                        }
                        let deep = total.saturating_sub(PROFILES_PAGE_SIZE);
                        for off in [0usize, total / 2, deep] {
                            let req = PageRequest {
                                view,
                                active_threshold: 0,
                                scope: PlanScope::All,
                                search: None,
                                group_id: None,
                                sort,
                                ascending: true,
                                offset: off,
                                limit: PROFILES_PAGE_SIZE,
                            };
                            let mut acc = Acc::new();
                            for _ in 0..5 {
                                let started = Instant::now();
                                let page = db.profiles_page(&req).await.expect("page");
                                acc.add(started.elapsed());
                                black_box(page.ids.len());
                            }
                            rows_out.push(
                                acc.row(&format!("profiles_page {vtag} {tag} offset={off}"), 1.0),
                            );
                        }
                    }
                }

                if total > 0 {
                    println!("real feed: {total} endpoints, sweep over Address and Test");
                }

                let ids = db.profiles_page(&request).await.expect("page").ids;
                let mut hydrate_acc = Acc::new();
                for _ in 0..10 {
                    let started = Instant::now();
                    let hydrated = db.load_page_projection(&ids, false).await.expect("hydrate");
                    hydrate_acc.add(started.elapsed());
                    black_box(hydrated.len());
                }
                rows_out.push(hydrate_acc.row("load_page_projection (real feed)", 1.0));

                // The per-tick reload the UI runs whenever a result landed.
                let feed_rows = db.load_page_projection(&ids, false).await.expect("hydrate");
                let mut ui_state = test_state(feed_rows).await;
                ui_state.db = Arc::clone(&db);
                let mut reload_acc = Acc::new();
                for _ in 0..10 {
                    let started = Instant::now();
                    crate::ops::profiles::reload_profiles_preserving_selection(&mut ui_state).await;
                    reload_acc.add(started.elapsed());
                }
                rows_out
                    .push(reload_acc.row("reload_profiles_preserving_selection (real feed)", 1.0));

                // The same reload split into its two halves: the DB read
                // (`load_profiles_rows`) and the in-memory apply.
                let mut load_half = Acc::new();
                let mut apply_half = Acc::new();
                for _ in 0..10 {
                    let load = crate::ops::profiles::ProfilesLoad::from(&ui_state);
                    let started = Instant::now();
                    let loaded = crate::ops::profiles::load_profiles_rows(&db, &load).await;
                    load_half.add(started.elapsed());
                    match loaded {
                        Ok((rows, meta)) => {
                            let started = Instant::now();
                            crate::ops::profiles::apply_profiles_rows(&mut ui_state, rows, &meta);
                            apply_half.add(started.elapsed());
                        }
                        Err(_) => {}
                    }
                }
                rows_out.push(load_half.row("reload half: load_profiles_rows", 1.0));
                rows_out.push(apply_half.row("reload half: apply_profiles_rows", 1.0));

                // Attribution of the reload: which half of it pays.
                let view_request = PageRequest {
                    view: PurgatoryView::Active,
                    active_threshold: leas_db::models::to_epoch(jiff::Timestamp::now())
                        - ui_state.purgatory_ttl_secs,
                    scope: PlanScope::All,
                    search: None,
                    group_id: None,
                    sort: PageSort::Test,
                    ascending: true,
                    offset: 0,
                    limit: PROFILES_PAGE_SIZE,
                };
                let mut acc = Acc::new();
                for _ in 0..10 {
                    let started = Instant::now();
                    let page = db.profiles_page(&view_request).await.expect("page");
                    acc.add(started.elapsed());
                    black_box(page.total);
                }
                rows_out.push(acc.row("profiles_page (Active view, Test sort)", 1.0));

                // Direction × sort: the reload uses the state's own pair, and a
                // mixed-direction composite index cannot serve the reverse of
                // every term.
                for (sort, ascending) in [(PageSort::Test, true), (PageSort::Test, false)] {
                    let request = PageRequest {
                        view: PurgatoryView::Active,
                        active_threshold: view_request.active_threshold,
                        scope: PlanScope::All,
                        search: None,
                        group_id: None,
                        sort,
                        ascending,
                        offset: 0,
                        limit: PROFILES_PAGE_SIZE,
                    };
                    let mut acc = Acc::new();
                    for _ in 0..5 {
                        let started = Instant::now();
                        let page = db.profiles_page(&request).await.expect("page");
                        acc.add(started.elapsed());
                        black_box(page.total);
                    }
                    rows_out.push(acc.row(
                        &format!("profiles_page view=Active {sort:?} asc={ascending}"),
                        1.0,
                    ));
                }

                let view_ids = db.profiles_page(&view_request).await.expect("page").ids;
                let mut acc = Acc::new();
                for _ in 0..10 {
                    let started = Instant::now();
                    let hydrated = db
                        .load_page_projection(&view_ids, false)
                        .await
                        .expect("hydrate");
                    acc.add(started.elapsed());
                    black_box(hydrated.len());
                }
                rows_out.push(acc.row("load_page_projection (Active view page)", 1.0));

                // NOTE: `apply_profiles_rows` also calls `spawn_enrich_ip_hosts`
                // and `spawn_outbound_countries`, whose mmdb work runs on this
                // same runtime in the background. That fan-out is deliberately
                // NOT re-measured in a loop here: 20 iterations of it pile up
                // thousands of geo lookups and inflate every later row.

                for (label, sql) in [
                    (
                        "host lengths (endpoints)",
                        "SELECT MIN(LENGTH(host)), MAX(LENGTH(host)), AVG(LENGTH(host)), \
                         SUM(CASE WHEN LENGTH(host) <= 24 THEN 1 ELSE 0 END), COUNT(*) \
                         FROM endpoints",
                    ),
                    (
                        "distinct protocols per link",
                        "SELECT COUNT(DISTINCT protocol_id), COUNT(*) FROM profile_stats",
                    ),
                    (
                        "error text lengths",
                        "SELECT AVG(LENGTH(error_text)), MAX(LENGTH(error_text)) FROM profile_stats WHERE error_text IS NOT NULL",
                    ),
                ] {
                    if let Ok(mut conn) = db.connection().await {
                        if let Ok(rows) = toasty::sql::query(sql).exec(&mut conn).await {
                            println!("[feed] {label}: {rows:?}");
                        }
                    }
                }

                // ── page-query shape experiments (same engine the app uses) ─
                // The tab's DEFAULT sort is Address; the walk uses it too. The
                // staged-key sorts are index-driven, so the question is whether
                // the host order can be driven from an index instead of a sort.
                let mut conn = db.connection().await.expect("conn");
                let _ = toasty::sql::query(
                    "CREATE INDEX IF NOT EXISTS idx_measure_host ON endpoints(domain, sub_domain, port)",
                )
                .exec(&mut conn)
                .await;

                let variants: [(&str, String); 6] = [
                    (
                        "raw: Address order, endpoint_rank-driven",
                        "SELECT k.endpoint_id FROM endpoint_rank k JOIN endpoints e ON e.id = k.endpoint_id \
                         WHERE k.rank_newest_seen >= ?1 ORDER BY e.domain ASC, e.sub_domain ASC, k.endpoint_id ASC LIMIT 200"
                            .to_owned(),
                    ),
                    (
                        "raw: id order, endpoint_rank-driven",
                        "SELECT k.endpoint_id FROM endpoint_rank k WHERE k.rank_newest_seen >= ?1 \
                         ORDER BY k.endpoint_id ASC LIMIT 200"
                            .to_owned(),
                    ),
                    (
                        "raw: Address order, forced host index",
                        "SELECT k.endpoint_id FROM endpoints e INDEXED BY idx_measure_host \
                         JOIN endpoint_rank k ON k.endpoint_id = e.id WHERE k.rank_newest_seen >= ?1 \
                         ORDER BY e.domain ASC, e.sub_domain ASC, k.endpoint_id ASC LIMIT 200"
                            .to_owned(),
                    ),
                    (
                        "raw: Address order, rank-driven + host join",
                        "SELECT k.endpoint_id FROM endpoint_rank k JOIN endpoints e ON e.id = k.endpoint_id \
                         WHERE k.rank_newest_seen >= ?1 ORDER BY e.domain ASC, e.sub_domain ASC LIMIT 200"
                            .to_owned(),
                    ),
                    (
                        "raw: Port order, rank-driven (filesort)",
                        "SELECT k.endpoint_id FROM endpoint_rank k JOIN endpoints e ON e.id = k.endpoint_id \
                         WHERE k.rank_newest_seen >= ?1 ORDER BY e.port ASC, k.endpoint_id ASC LIMIT 200"
                            .to_owned(),
                    ),
                    (
                        "raw: Ip order, rank-driven (filesort)",
                        "SELECT k.endpoint_id FROM endpoint_rank k WHERE k.rank_newest_seen >= ?1 \
                         ORDER BY COALESCE((SELECT min(ip.ip_key) FROM endpoint_ip ip \
                         WHERE ip.endpoint_id = k.endpoint_id), x'ff') ASC, k.endpoint_id ASC LIMIT 200"
                            .to_owned(),
                    ),
                ];
                for (label, sql) in variants {
                    let mut acc = Acc::new();
                    for _ in 0..8 {
                        let started = Instant::now();
                        let result = toasty::sql::query(sql.clone())
                            .bind(0_i64)
                            .exec(&mut conn)
                            .await;
                        match result {
                            Ok(rows) => {
                                acc.add(started.elapsed());
                                black_box(rows.len());
                            }
                            Err(e) => {
                                println!("[{label}] failed: {e}");
                                break;
                            }
                        }
                    }
                    if !acc.samples.is_empty() {
                        rows_out.push(acc.row(label, 1.0));
                    }
                }
                drop(conn);

                // The batch's feed walk: page + hydrate per page, no probes.
                let mut offset = 0usize;
                let mut pages = 0u32;
                let mut links_seen = 0usize;
                let started = Instant::now();
                loop {
                    let request = PageRequest {
                        view: PurgatoryView::All,
                        active_threshold: 0,
                        scope: PlanScope::All,
                        search: None,
                        group_id: None,
                        sort: PageSort::Id,
                        ascending: true,
                        offset,
                        limit: PROFILES_PAGE_SIZE,
                    };
                    let (ids, total) = db
                        .profiles_walk_page(&request, offset == 0)
                        .await
                        .expect("walk");
                    if ids.is_empty() {
                        break;
                    }
                    offset += ids.len();
                    pages += 1;
                    let walked = db.load_page_projection(&ids, false).await.expect("hydrate");
                    links_seen += walked.iter().map(|r| r.links.len()).sum::<usize>();
                    if total.is_some_and(|t| offset as u64 >= t) {
                        break;
                    }
                }
                println!(
                    "[feed] plan walk: {pages} pages, {links_seen} links, {:.1} ms total, {:.1} ms/page",
                    started.elapsed().as_secs_f64() * 1000.0,
                    started.elapsed().as_secs_f64() * 1000.0 / f64::from(pages.max(1)),
                );
                rows_out.push(TableRow {
                    name: "plan walk (page+hydrate, per page, id order)".to_owned(),
                    ns: started.elapsed().as_nanos() as f64 / f64::from(pages.max(1)),
                    n: pages,
                });

                // ── band A/B (P1b): does an equality-seek beat the Address
                // filesort on the REAL feed's own Active/stale distribution?
                // Scratch columns on the feed COPY (never the live file), run
                // last so nothing measured above is affected.
                let threshold = leas_db::models::now_epoch() - 7 * 86400;
                // Copy the feed (+ WAL sidecars) into a TempDir and mutate ONLY
                // the copy: the ALTER/CREATE INDEX below must never touch the
                // file the var points at, even a live data.db.
                let scratch_dir = tempfile::tempdir().expect("tempdir");
                let scratch_path = scratch_dir.path().join("scratch.db");
                let mut have_copy = false;
                for suffix in ["", "-wal", "-shm"] {
                    let src = format!("{path}{suffix}");
                    if std::path::Path::new(&src).exists() {
                        let dst = scratch_dir.path().join(format!("scratch.db{suffix}"));
                        if std::fs::copy(&src, &dst).is_ok() && suffix.is_empty() {
                            have_copy = true;
                        }
                    }
                }
                let scratch_db = if have_copy {
                    leas_db::Database::open(&scratch_path).await.ok()
                } else {
                    None
                };
                if let Some(scratch_db) = &scratch_db
                    && let Ok(mut conn) = scratch_db.connection().await
                {
                    for ddl in [
                        "ALTER TABLE endpoint_rank ADD COLUMN mband INTEGER",
                        "ALTER TABLE endpoint_rank ADD COLUMN rank_host TEXT",
                    ] {
                        let _ = toasty::sql::query(ddl).exec(&mut conn).await;
                    }
                    let _ = toasty::sql::query(&format!(
                        "UPDATE endpoint_rank SET mband = CASE WHEN rank_newest_seen >= {threshold} \
                         THEN 0 ELSE 1 END"
                    ))
                    .exec(&mut conn)
                    .await;
                    let _ = toasty::sql::query(
                        "UPDATE endpoint_rank SET rank_host = \
                         (SELECT host FROM endpoints e WHERE e.id = endpoint_rank.endpoint_id)",
                    )
                    .exec(&mut conn)
                    .await;
                    let _ = toasty::sql::query(
                        "CREATE INDEX IF NOT EXISTS idx_measure_band_host \
                         ON endpoint_rank(mband, rank_host, endpoint_id)",
                    )
                    .exec(&mut conn)
                    .await;
                    let band_ab: [(&str, String); 2] = [
                        (
                            "band A/B: Address filesort (baseline)",
                            format!(
                                "SELECT k.endpoint_id FROM endpoint_rank k \
                                 JOIN endpoints e ON e.id = k.endpoint_id \
                                 WHERE k.rank_newest_seen >= {threshold} \
                                 ORDER BY e.domain ASC, e.sub_domain ASC, k.endpoint_id ASC LIMIT 200"
                            ),
                        ),
                        (
                            "band A/B: band=0 seek (rank_host)",
                            "SELECT endpoint_id FROM endpoint_rank WHERE mband = 0 \
                             ORDER BY rank_host ASC, endpoint_id ASC LIMIT 200"
                                .to_owned(),
                        ),
                    ];
                    for (label, sql) in band_ab {
                        let mut acc = Acc::new();
                        for _ in 0..8 {
                            let started = Instant::now();
                            match toasty::sql::query(sql.clone()).exec(&mut conn).await {
                                Ok(rows) => {
                                    acc.add(started.elapsed());
                                    black_box(rows.len());
                                }
                                Err(e) => {
                                    println!("[{label}] failed: {e}");
                                    break;
                                }
                            }
                        }
                        if !acc.samples.is_empty() {
                            rows_out.push(acc.row(label, 1.0));
                        }
                    }
                }
            }
            Err(e) => println!("[real feed] open failed: {e}"),
        }
    }

    measure_page_scale().await;
    print_table("fast + real ping flow", &rows_out);
}

/// E1/E2/E3 at synthetic scale (gated by `LEAS_SCALE`). Seeds a temp feed
/// at each N, materializes rank keys, then measures the Active page for the
/// filesort sorts (Address/Port) and the index sort (Test) across offsets, plus
/// the band-seek A/B — the P1b before/after, at scale.
async fn measure_page_scale() {
    let Ok(spec) = std::env::var("LEAS_SCALE") else {
        return;
    };
    let sizes: Vec<usize> = if spec.trim().is_empty() || spec.trim() == "1" {
        vec![7686, 50000, 200000]
    } else {
        spec.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    };
    let now = leas_db::models::now_epoch();
    let ttl = 7 * 86400_i64;
    let threshold = now - ttl;
    for n in sizes {
        let dir = tempfile::tempdir().unwrap();
        let db = match leas_db::Database::open(dir.path().join("scale.db")).await {
            Ok(d) => d,
            Err(e) => {
                println!("[scale N={n}] open failed: {e}");
                continue;
            }
        };
        // last_seen_at spread across the Active boundary (~half Active), so the
        // view filter and the band split are both meaningful.
        let mut rows = synth_rows(n, 2);
        for (i, row) in rows.iter_mut().enumerate() {
            let age = (i as i64 % (2 * ttl / 3600)) * 3600;
            let seen = now - age;
            for link in &mut row.links {
                link.last_seen_at = seen;
            }
        }
        for chunk in rows.chunks(5000) {
            let endpoints: Vec<_> = chunk.iter().map(|r| r.endpoint.clone()).collect();
            let protocols: Vec<_> = chunk
                .iter()
                .flat_map(|r| r.protocols.values().cloned())
                .collect();
            let links: Vec<_> = chunk.iter().flat_map(|r| r.links.iter().cloned()).collect();
            let mut conn = db.connection().await.expect("conn");
            let mut tx = conn.transaction().await.expect("tx");
            leas_db::upsert_endpoints_bulk(&mut tx, &endpoints)
                .await
                .expect("ep");
            leas_db::upsert_protocols_bulk(&mut tx, &protocols)
                .await
                .expect("pr");
            leas_db::upsert_links_bulk(&mut tx, &links)
                .await
                .expect("lk");
            tx.commit().await.expect("commit");
        }
        db.repair_endpoint_ranks().await.expect("ranks");

        let mut out: Vec<TableRow> = Vec::new();
        let active_total = {
            let req = PageRequest {
                view: PurgatoryView::Active,
                active_threshold: threshold,
                scope: PlanScope::All,
                search: None,
                group_id: None,
                sort: PageSort::Id,
                ascending: true,
                offset: 0,
                limit: PROFILES_PAGE_SIZE,
            };
            db.profiles_page(&req)
                .await
                .map(|p| p.total as usize)
                .unwrap_or(0)
        };
        let offsets = [
            0usize,
            active_total / 2,
            active_total.saturating_sub(PROFILES_PAGE_SIZE),
        ];
        for (sort, tag) in [
            (PageSort::Port, "Port(filesort)"),
            (PageSort::Test, "Test(index)"),
        ] {
            for &off in &offsets {
                let req = PageRequest {
                    view: PurgatoryView::Active,
                    active_threshold: threshold,
                    scope: PlanScope::All,
                    search: None,
                    group_id: None,
                    sort,
                    ascending: true,
                    offset: off,
                    limit: PROFILES_PAGE_SIZE,
                };
                let mut acc = Acc::new();
                for _ in 0..5 {
                    let started = Instant::now();
                    let p = db.profiles_page(&req).await.expect("page");
                    acc.add(started.elapsed());
                    black_box(p.ids.len());
                }
                out.push(acc.row(&format!("Active {tag} offset={off}"), 1.0));
            }
        }
        if let Ok(mut conn) = db.connection().await {
            for ddl in [
                "ALTER TABLE endpoint_rank ADD COLUMN mband INTEGER",
                "ALTER TABLE endpoint_rank ADD COLUMN rank_host TEXT",
            ] {
                let _ = toasty::sql::query(ddl).exec(&mut conn).await;
            }
            let _ = toasty::sql::query(&format!(
                "UPDATE endpoint_rank SET mband = CASE WHEN rank_newest_seen >= {threshold} \
                 THEN 0 ELSE 1 END"
            ))
            .exec(&mut conn)
            .await;
            let _ = toasty::sql::query(
                "UPDATE endpoint_rank SET rank_host = \
                 (SELECT host FROM endpoints e WHERE e.id = endpoint_rank.endpoint_id)",
            )
            .exec(&mut conn)
            .await;
            let _ = toasty::sql::query(
                "CREATE INDEX IF NOT EXISTS idx_measure_band_host \
                 ON endpoint_rank(mband, rank_host, endpoint_id)",
            )
            .exec(&mut conn)
            .await;
            let band_ab: [(String, String); 2] = [
                (
                    "band A/B: Address filesort".to_owned(),
                    format!(
                        "SELECT k.endpoint_id FROM endpoint_rank k \
                         JOIN endpoints e ON e.id = k.endpoint_id \
                         WHERE k.rank_newest_seen >= {threshold} \
                         ORDER BY e.domain ASC, e.sub_domain ASC, k.endpoint_id ASC LIMIT 200"
                    ),
                ),
                (
                    "band A/B: band=0 seek".to_owned(),
                    "SELECT endpoint_id FROM endpoint_rank WHERE mband = 0 \
                     ORDER BY rank_host ASC, endpoint_id ASC LIMIT 200"
                        .to_owned(),
                ),
            ];
            for (label, sql) in band_ab {
                let mut acc = Acc::new();
                for _ in 0..8 {
                    let started = Instant::now();
                    match toasty::sql::query(sql.clone()).exec(&mut conn).await {
                        Ok(r) => {
                            acc.add(started.elapsed());
                            black_box(r.len());
                        }
                        Err(e) => {
                            println!("[{label}] failed: {e}");
                            break;
                        }
                    }
                }
                if !acc.samples.is_empty() {
                    out.push(acc.row(&label, 1.0));
                }
            }
        }
        print_table(
            &format!("page scale N={n} (Active total={active_total})"),
            &out,
        );
    }
}

/// The one row the lab could not produce: the REAL level's network cost.
///
/// Every other section probes through `NullRunner`, so the real level's cost —
/// the long pole a batch is bound by — is measured nowhere. This runs the
/// PRODUCTION runner (`EngineProbeRunner`) over a pinned slice of a real feed,
/// and a direct per-attempt pass for the latency distribution.
///
/// Knobs (all optional except the DB; the slice descriptor is printed so a run
/// is reproducible):
///   `LEAS_MEASURE_DB`           path to a COPY of data.db (required)
///   `LEAS_MEASURE_MAX_LINKS`    slice size in links (default 15000)
///   `LEAS_MEASURE_CONCURRENCY`  real level concurrency (default 256)
///   `LEAS_MEASURE_BUDGET_SECS`  per-attempt budget (default 5)
///   `LEAS_MEASURE_SAMPLE`       links in the latency sample (default 400)
///
/// **What the measured span includes.** The batch's real half caches a loaded
/// protocol per batch, so a run pays one `load_protocol_with_config` per
/// distinct protocol it touches — that is inside the timed region and is part
/// of what a production batch pays too, but it means the absolute is not "probe
/// only". The before/after ratio stays valid because the slice and its protocol
/// count are pinned. The per-attempt pass (below) has no such term, which is
/// why the budget rule reads its distribution and not the batch's wall time.
///
/// **The harness-only knobs are the only difference from production**:
/// `real_concurrency`/`fast_concurrency` are raised here and nowhere else;
/// `dedup_endpoints` stays OFF and `real_phase` stays true, so the run is the
/// batch's own shape rather than a tuned variant.
#[ignore = "perf lab: run explicitly with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_cost_network() {
    let Ok(path) = std::env::var("LEAS_MEASURE_DB") else {
        println!("SKIP flow_cost_network: set LEAS_MEASURE_DB=<copy of data.db>");
        return;
    };
    let max_links = env_usize("LEAS_MEASURE_MAX_LINKS", 15_000);
    let concurrency = env_usize("LEAS_MEASURE_CONCURRENCY", 256);
    let budget = Duration::from_secs(env_usize("LEAS_MEASURE_BUDGET_SECS", 5) as u64);
    let sample_size = env_usize("LEAS_MEASURE_SAMPLE", 400);
    const PING_URL: &str = "https://www.gstatic.com/generate_204";

    let db = Arc::new(
        leas_db::Database::open(&path)
            .await
            .expect("open measure db"),
    );

    // Pin the slice: page in ID order — an order no write can move — until the
    // cap. The descriptor is printed so the same slice can be re-run.
    let mut rows: Vec<EndpointRow> = Vec::new();
    let mut links = 0usize;
    let mut offset = 0usize;
    loop {
        if links >= max_links {
            break;
        }
        let request = PageRequest {
            view: PurgatoryView::All,
            active_threshold: 0,
            scope: PlanScope::All,
            search: None,
            group_id: None,
            sort: PageSort::Id,
            ascending: true,
            offset,
            limit: PROFILES_PAGE_SIZE,
        };
        let ids = db.profiles_page(&request).await.expect("page").ids;
        if ids.is_empty() {
            break;
        }
        let page = db.load_page_projection(&ids, true).await.expect("hydrate");
        links += page.iter().map(|r| r.links.len()).sum::<usize>();
        rows.extend(page);
        offset += PROFILES_PAGE_SIZE;
    }
    let plan: Vec<PlanLink> = rows
        .iter()
        .flat_map(plan_row_links)
        .take(max_links)
        .collect();
    let planned = plan.len();
    let protocols: std::collections::HashSet<_> = plan.iter().map(|p| p.link.protocol_id).collect();
    println!(
        "[network] slice: {planned} links over {} endpoints, {} distinct protocols \
         (ID order, offset 0..{offset})",
        rows.len(),
        protocols.len()
    );
    println!(
        "[network] harness-only knobs: concurrency {concurrency} (production default 100, \
         this lab's other sections 64), budget {}s; dedup_endpoints OFF, real_phase true",
        budget.as_secs()
    );

    // ── the batch's own shape, through the production runner ───────────
    let mut state = test_state(rows.clone()).await;
    // The feed for the protocol loads; the run's own writes land in the lab's
    // temp db through the writer, which is what a lab run wants.
    state.db = Arc::clone(&db);
    let (tx, rx) = mpsc::channel::<CoreEvent>(1 << 16);
    let mut params = batch_params(
        &state,
        tx,
        plan,
        true,
        PROFILES_PAGE_SIZE,
        Arc::new(EngineProbeRunner),
    );
    params.real_concurrency = concurrency;
    params.fast_concurrency = concurrency;
    params.real_timeout = budget;
    params.dedup_endpoints = false;
    params.ping_url = PING_URL.to_owned();
    params.ip_provider = IpProvider::IpApi;
    let slot = Arc::clone(&params.batch_slot);
    let started = Instant::now();
    run_batch(params).await;
    let elapsed = started.elapsed();
    drop(rx);
    // The batch's own summary line, not a re-derivation: the lab and the app
    // then report the same numbers by construction.
    if let Some(shared) = slot.get() {
        use std::sync::atomic::Ordering;
        println!("[summary] {}", summary_line(shared));
        let done = u64::from(shared.counters.real_ok.load(Ordering::Relaxed))
            + u64::from(shared.counters.real_failed.load(Ordering::Relaxed));
        println!(
            "[network] real results {done} in {:.1} s = {:.2} results/s",
            elapsed.as_secs_f64(),
            done as f64 / elapsed.as_secs_f64()
        );
    } else {
        println!("[network] no batch handle published — the run never started");
    }

    // ── the per-attempt distribution (the budget rule's input) ─────────
    //
    // `real_ping` with `retries: 1` measures ONE attempt's span — dial →
    // protocol → target → response head — with no batch, no writer and no
    // per-protocol cache term, so this is the number the budget default must
    // clear. Sequential on purpose: the point is the span, not throughput.
    let mut latencies: Vec<u64> = Vec::new();
    let mut failures = 0usize;
    // Failure spans, binned by class. Basis 2 needs the p99 over attempts that
    // failed for a reason OTHER than a deadline, and nothing else records a
    // failure's duration (`ProbeFailure` carries class + text only), so the
    // sample times each attempt itself. `Timeout` is the only hang class —
    // every other variant is a peer or local answer, so its span is bounded by
    // the work rather than by the budget.
    let mut failure_spans: std::collections::BTreeMap<ProbeClass, Vec<u64>> =
        std::collections::BTreeMap::new();
    // The sample pass is SEQUENTIAL on purpose — concurrent attempts contend for
    // the CPU-bound handshake and would inflate every span. Sequential makes its
    // wall time the sum of its attempts, and most attempts here are failures
    // that run to the full budget, so it gets a deadline of its own: the
    // distribution is what matters, not how many samples fit.
    let sample_deadline =
        Duration::from_secs(env_usize("LEAS_MEASURE_SAMPLE_DEADLINE_SECS", 300) as u64);
    let sample_started = Instant::now();
    let req = NativeProbeReq {
        ping_url: PING_URL,
        ip_provider: IpProvider::IpApi,
        timeout: budget,
        retries: 1,
    };
    'sample: for row in rows.iter() {
        if latencies.len() >= sample_size {
            break;
        }
        for link in row.links.iter() {
            if latencies.len() >= sample_size || sample_started.elapsed() >= sample_deadline {
                break 'sample;
            }
            let Ok(Some(protocol)) =
                crate::state::load_protocol_with_config(&db, link.protocol_id).await
            else {
                continue;
            };
            // `Deferred<Json<_>>::get()` — the same accessor the batch's
            // `protocol_config` uses, so an unloaded row fails here exactly as
            // it fails on the production path.
            let config = protocol.config.get().0.clone();
            let attempt = Instant::now();
            match crate::ops::ping_native::real_ping(&row.endpoint, &[], &config, &req).await {
                Ok(r) => latencies.push(r.latency_ms),
                Err(failure) => {
                    failures += 1;
                    failure_spans
                        .entry(failure.class)
                        .or_default()
                        .push(attempt.elapsed().as_millis() as u64);
                }
            }
        }
    }
    latencies.sort_unstable();
    if let (Some(min), Some(max)) = (latencies.first(), latencies.last()) {
        let pct = |p: f64| latencies[((latencies.len() as f64 - 1.0) * p) as usize];
        println!(
            "[network] per-attempt successes: {} (failures {failures}) | min {min} ms | \
             median {} ms | p90 {} ms | p99 {} ms | max {max} ms",
            latencies.len(),
            pct(0.50),
            pct(0.90),
            pct(0.99)
        );
    } else {
        println!("[network] per-attempt sample produced no successes (failures {failures})");
    }

    // ── basis 2: the p99 over NON-hang failures ────────────────────────
    //
    // The budget default must clear the span of an attempt that did real work,
    // so the population is every failure class except `Timeout` — a deadline
    // span says nothing about how long the work takes. This is the basis that
    // works on a feed where successes are ~1 %.
    let mut non_hang: Vec<u64> = Vec::new();
    for (class, spans) in &failure_spans {
        let mut sorted = spans.clone();
        sorted.sort_unstable();
        let pct = |p: f64| sorted[((sorted.len() as f64 - 1.0) * p) as usize];
        let tag = if *class == ProbeClass::Timeout {
            "hang"
        } else {
            non_hang.extend_from_slice(spans);
            "counts"
        };
        println!(
            "[network] failure spans {class:?} ({tag}): n={} median {} ms p90 {} ms max {} ms",
            sorted.len(),
            pct(0.50),
            pct(0.90),
            sorted[sorted.len() - 1]
        );
    }
    if non_hang.is_empty() {
        println!("[network] basis 2: no non-hang failures sampled — no p99 available");
    } else {
        non_hang.sort_unstable();
        let pct = |p: f64| non_hang[((non_hang.len() as f64 - 1.0) * p) as usize];
        println!(
            "[network] basis 2 (p99 over non-hang attempt spans, n={}): median {} ms | \
             p90 {} ms | p99 {} ms | max {} ms",
            non_hang.len(),
            pct(0.50),
            pct(0.90),
            pct(0.99),
            non_hang[non_hang.len() - 1]
        );
        if non_hang.len() < 100 {
            println!(
                "[network] WARNING: n={} is thin for a p99 — raise \
                 LEAS_MEASURE_SAMPLE_DEADLINE_SECS",
                non_hang.len()
            );
        }
    }
}

/// The control instrument for the HTTP-transport divergence (item 7).
///
/// Records what the PROBE reports for a pinned set of links — the failure CLASS
/// and TEXT, not an HTTP status. The CDN 403/409 is a transport-handshake
/// failure surfacing as `ProbeOutcome::Failed { class: Transport, text:
/// "httpupgrade: expected 101, got 403" }`; the probe's own HTTP status is the
/// *target's* (gstatic's 204), so a status distribution would read the wrong
/// layer and the A/B would have no usable control.
///
/// Per-attempt and sequential, exactly like the budget sample: the question is
/// what the wire produces, not how fast.
///
/// Knobs:
///   `LEAS_MEASURE_DB`         path to a COPY of data.db (required)
///   `LEAS_MEASURE_PROTO_IDS`  comma-separated protocol ids (required)
///   `LEAS_MEASURE_BUDGET_SECS` per-attempt budget (default 5)
#[ignore = "perf lab: run explicitly with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_cost_transport_control() {
    let Ok(path) = std::env::var("LEAS_MEASURE_DB") else {
        println!("SKIP flow_cost_transport_control: set LEAS_MEASURE_DB");
        return;
    };
    let Ok(ids_raw) = std::env::var("LEAS_MEASURE_PROTO_IDS") else {
        println!("SKIP flow_cost_transport_control: set LEAS_MEASURE_PROTO_IDS");
        return;
    };
    let budget = Duration::from_secs(env_usize("LEAS_MEASURE_BUDGET_SECS", 5) as u64);
    const PING_URL: &str = "https://www.gstatic.com/generate_204";

    let wanted: std::collections::HashSet<i64> = ids_raw
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect();
    assert!(!wanted.is_empty(), "no parsable ids in {ids_raw:?}");

    let db = Arc::new(
        leas_db::Database::open(&path)
            .await
            .expect("open measure db"),
    );

    // Find each wanted protocol's (endpoint, link) by paging the feed. The
    // walk stops as soon as every id is accounted for, so a pinned set costs a
    // few pages, not a feed scan.
    let mut found: Vec<(Endpoint, ProtocolId, ProtocolConfig)> = Vec::new();
    let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut offset = 0usize;
    'walk: loop {
        let request = PageRequest {
            view: PurgatoryView::All,
            active_threshold: 0,
            scope: PlanScope::All,
            search: None,
            group_id: None,
            sort: PageSort::Id,
            ascending: true,
            offset,
            limit: PROFILES_PAGE_SIZE,
        };
        let page_ids = db.profiles_page(&request).await.expect("page").ids;
        if page_ids.is_empty() {
            break;
        }
        let page = db
            .load_page_projection(&page_ids, true)
            .await
            .expect("hydrate");
        for row in &page {
            for link in &row.links {
                let raw = link.protocol_id.get();
                if !wanted.contains(&raw) || !seen.insert(raw) {
                    continue;
                }
                let Ok(Some(protocol)) =
                    crate::state::load_protocol_with_config(&db, link.protocol_id).await
                else {
                    continue;
                };
                found.push((
                    row.endpoint.clone(),
                    link.protocol_id,
                    protocol.config.get().0.clone(),
                ));
                if seen.len() == wanted.len() {
                    break 'walk;
                }
            }
        }
        offset += PROFILES_PAGE_SIZE;
    }
    println!(
        "[control] requested {} protocol id(s), resolved {}",
        wanted.len(),
        found.len()
    );

    let req = NativeProbeReq {
        ping_url: PING_URL,
        ip_provider: IpProvider::IpApi,
        timeout: budget,
        retries: 1,
    };
    let mut histogram: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut ok = 0usize;
    for (endpoint, protocol_id, config) in &found {
        let key = match crate::ops::ping_native::real_ping(endpoint, &[], config, &req).await {
            Ok(_) => {
                ok += 1;
                "OK".to_owned()
            }
            Err(failure) => format!("{:?}: {}", failure.class, failure.text),
        };
        println!("[control] {} -> {key}", protocol_id.get());
        *histogram.entry(key).or_default() += 1;
    }
    println!("[control] ok={ok} of {} — distribution:", found.len());
    for (key, n) in &histogram {
        println!("[control]   {n:>4}  {key}");
    }
}

/// `LEAS_MEASURE_*` knob: a positive integer, or the default.
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// A 64-bit FNV-1a hash: the no-allocation dedup key a `(u64, u16)` map needs.
fn fnv(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// Time `poll_core_events` over 2000 results whose endpoint is (or is not) on
/// the loaded page.
async fn hit_miss_rows(hit: bool) -> Vec<TableRow> {
    let page = synth_rows(200, 4);
    let mut state = test_state(page.clone()).await;
    let (tx, rx) = mpsc::channel::<CoreEvent>(1 << 16);
    state.core_event_tx = Some(tx.clone());
    state.core_event_rx = Some(rx);
    let (endpoint_id, protocol_id) = if hit {
        (
            page[0].endpoint.id.get(),
            page[0].links[0].protocol_id.get(),
        )
    } else {
        (9_000_001, 900_000_101)
    };
    let results = 2000;
    let started = Instant::now();
    for _ in 0..results {
        let _ = tx.try_send(CoreEvent::TestTypeUpdate {
            endpoint_id,
            protocol_id,
            test_type: TestType::TcpPing,
        });
        let _ = tx.try_send(CoreEvent::SpeedTestResult {
            endpoint_id,
            protocol_id,
            test_type: TestType::TcpPing,
            latency_ms: Some(12),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        });
    }
    while state.poll_core_events().await {}
    let elapsed = started.elapsed();
    drop(tx);
    let label = if hit { "row on page" } else { "row off page" };
    vec![TableRow {
        name: format!("poll_core_events per result ({label})"),
        ns: elapsed.as_nanos() as f64 / f64::from(results),
        n: 1,
    }]
}

/// The four row families of one import transaction. Every row carries the
/// values it already holds, so replaying a batch is idempotent.
#[derive(Clone, Default)]
struct ImportBatch {
    endpoints: Vec<Endpoint>,
    protocols: Vec<leas_db::models::Protocol>,
    links: Vec<ProfileStats>,
    group_links: Vec<leas_db::models::EndpointGroup>,
}

impl ImportBatch {
    fn len(&self) -> usize {
        self.links.len()
    }

    fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// One import transaction — all four bulk families in a single commit, the
/// exact shape `stream_import::persist_batch` writes.
///
/// All four, not just the links: `upsert_endpoints_bulk`,
/// `upsert_protocols_bulk` and `upsert_endpoint_group_links_bulk` are the
/// PER-ROW writers, and `upsert_links_bulk` is the one already chunked at
/// `LINK_STATEMENT_ROWS`. Replaying only the links would measure the writer that
/// is NOT the subject, and this row is worthless as a before/after for the
/// import-upsert work if it does.
async fn write_import_once(
    db: Arc<leas_db::Database>,
    batch: Arc<ImportBatch>,
) -> leas_db::Result<()> {
    let mut conn = db.connection().await?;
    let mut tx = conn.transaction().await?;
    leas_db::upsert_endpoints_bulk(&mut tx, &batch.endpoints).await?;
    leas_db::upsert_protocols_bulk(&mut tx, &batch.protocols).await?;
    leas_db::upsert_links_bulk(&mut tx, &batch.links).await?;
    leas_db::upsert_endpoint_group_links_bulk(&mut tx, &batch.group_links).await?;
    tx.commit().await?;
    Ok(())
}

/// Per-arm failure accounting. A single shared counter let a run in which
/// EVERY import transaction failed report a plausible-looking millisecond figure
/// for two consecutive runs; the only symptom was a failure total nobody could
/// attribute. Every arm now owns its own counter, and an arm that failed on
/// every sample is called out by name instead of being averaged into the table.
struct ArmFailures {
    arm: &'static str,
    samples: usize,
    failures: usize,
}

impl ArmFailures {
    const fn new(arm: &'static str) -> Self {
        Self {
            arm,
            samples: 0,
            failures: 0,
        }
    }

    fn record(&mut self, ok: bool) {
        self.samples += 1;
        self.failures += usize::from(!ok);
    }

    /// Returns true when the arm is unusable as a measurement.
    fn report(&self) -> bool {
        if self.samples == 0 {
            println!("  arm {:<44} NO SAMPLES — not a measurement", self.arm);
            return true;
        }
        if self.failures == self.samples {
            println!(
                "  arm {:<44} FAILED ON ALL {} SAMPLES — DISCARD this row",
                self.arm, self.samples
            );
            return true;
        }
        println!(
            "  arm {:<44} {}/{} writes failed",
            self.arm, self.failures, self.samples
        );
        false
    }
}

/// Split a slice into `n` transactions of roughly `per_tx` links, keeping all
/// four families consistent: whole endpoint units only, so a protocol or group
/// link is never separated from its endpoint.
///
/// Without this, every "transaction" replays the WHOLE slice — ~9x production's
/// ~500-URL batch — and the row is useless as the import-upsert task's reference.
fn split_batches(slice: &ImportBatch, n: usize, per_tx: usize) -> Vec<ImportBatch> {
    let mut out: Vec<ImportBatch> = Vec::new();
    let mut cur = ImportBatch::default();
    let mut cursor = 0usize;
    while cursor < slice.links.len() {
        let endpoint_id = slice.links[cursor].endpoint_id;
        // How many consecutive links belong to this endpoint?
        let end = slice.links[cursor..]
            .iter()
            .position(|link| link.endpoint_id != endpoint_id)
            .map_or(slice.links.len(), |skip| cursor + skip);
        let unit = &slice.links[cursor..end];
        if !cur.links.is_empty() && cur.links.len() + unit.len() > per_tx {
            out.push(std::mem::take(&mut cur));
            if out.len() == n {
                return out;
            }
        }
        if let Some(idx) = slice.endpoints.iter().position(|e| e.id == endpoint_id) {
            cur.endpoints.push(slice.endpoints[idx].clone());
        }
        for protocol in slice
            .protocols
            .iter()
            .filter(|p| unit.iter().any(|l| l.protocol_id == p.id))
        {
            cur.protocols.push(protocol.clone());
        }
        for gl in slice
            .group_links
            .iter()
            .filter(|gl| gl.endpoint_id == endpoint_id)
        {
            cur.group_links.push(gl.clone());
        }
        cur.links.extend_from_slice(unit);
        cursor = end;
    }
    if !cur.links.is_empty() {
        out.push(cur);
    }
    out
}

/// Replays the **import + geo + link-writer** write mix against the real measure
/// database.
///
/// `specs/2026-09-24-turso-mvcc-rollout-design.md` §DB-API A/B probed this mix
/// (8×800-link import transactions + 16×100-row country flushes, 5 repetitions,
/// WAL-vs-MVCC) and then declared it **disposable** — which is why the open
/// "production workload benchmark" has no harness. It is the same mix the
/// 2026-10-01 production run spent its write budget in, so it lives here now.
///
/// Four rows, each answering a different question:
///   1-2. sequential import tx / geo flush — per-operation cost, nothing else running
///   3.   **fan-in** — import and geo writers OVERLAPPING. Every other row in this
///        module is sequential, and only this shape reproduces the `snapshot is
///        stale` aborts; without it there is no contention to measure.
///        **As of 2026-10-05 the IMPORT half is unusable** — the AFTER-NUMBERS
///        block further down inside this function explains why; the geo arms and
///        the trickle row carry the measurement until the slice is rebuilt with
///        protocol `config` loaded.
///   4.   **flush trickle** — the link writer driven on a wall-clock ARRIVAL
///        schedule, reporting `flush_count()`. Rows-per-flush is set by arrival
///        rate, not row count: staging 4,028 rows in a tight loop trips the
///        512-row size trigger and yields ~8 flushes, while the production
///        trickle (~3.45 rows per 200 ms tick) produced 1,167.
///
/// The geo half replays addresses that already carry a country. A `None` country
/// is skipped, never given a placeholder — `set_endpoint_ip_countries` takes a
/// concrete `String`, so writing one would persist a fake ISO code into the very
/// column the WAL-vs-MVCC comparison reads. Addresses come from
/// `endpoint_resolutions` (i.e. `endpoint_ip`), not the page row's `resolved_ips`,
/// because the abort path is an UPDATE that misses or an INSERT that races;
/// replaying an address with no `endpoint_ip` row measures the wrong statement.
///
/// All four families are idempotent replays. Run against a COPY.
///
/// **The MVCC arm cannot come from this path.** An existing file stays WAL
/// (`read_version=2`); MVCC needs a fresh file created with
/// `LEAS_TURSO_CONCURRENT_WRITES=1`. The synthetic-feed builder in
/// `measure_page_scale` is the piece to reuse for that arm — not a second copy.
///
/// Knobs:
///   `LEAS_MEASURE_DB`             path to a COPY of data.db (required)
///   `LEAS_MEASURE_REPS`           repetitions of the whole mix (default 5)
///   `LEAS_MEASURE_IMPORT_TX`      import transactions per rep (default 8)
///   `LEAS_MEASURE_LINKS_PER_TX`   links per import tx (default 800)
///   `LEAS_MEASURE_GEO_FLUSH`      country flushes per rep (default 16)
///   `LEAS_MEASURE_ROWS_PER_FLUSH` addresses per country flush (default 100)
///   `LEAS_MEASURE_FANIN`          concurrent writer tasks (default 16)
///   `LEAS_MEASURE_TRICKLE_ROWS`   link-writer arrivals (default 4_028)
///   `LEAS_MEASURE_TRICKLE_RPS`    arrival rate, rows/s (default 12)
#[ignore = "perf lab: run explicitly with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_cost_contention() {
    let Ok(path) = std::env::var("LEAS_MEASURE_DB") else {
        println!("SKIP flow_cost_contention: set LEAS_MEASURE_DB=<copy of data.db>");
        return;
    };
    let reps = env_usize("LEAS_MEASURE_REPS", 5);
    let import_tx = env_usize("LEAS_MEASURE_IMPORT_TX", 8);
    let links_per_tx = env_usize("LEAS_MEASURE_LINKS_PER_TX", 800);
    let geo_flush = env_usize("LEAS_MEASURE_GEO_FLUSH", 16);
    let rows_per_flush = env_usize("LEAS_MEASURE_ROWS_PER_FLUSH", 100);
    let fanin = env_usize("LEAS_MEASURE_FANIN", 16).max(1);
    let trickle_rows = env_usize("LEAS_MEASURE_TRICKLE_ROWS", 4_028);
    let trickle_rps = env_usize("LEAS_MEASURE_TRICKLE_RPS", 12).max(1);

    let db = Arc::new(
        leas_db::Database::open(&path)
            .await
            .expect("open measure db"),
    );
    println!(
        "\nmeasure db: {path}\njournal mode: {}",
        if db.uses_concurrent_writes() {
            "MVCC (concurrent_writes)"
        } else {
            "WAL"
        }
    );

    // Pre-flight: `Database::open` DESTROYS a file whose `user_version` does not
    // match (database.rs:274-288 — it calls `push_schema`, and on error drops
    // the file and rebuilds). A wiped or re-created copy therefore opens cleanly
    // with an empty schema, and an empty slice would otherwise be recorded as a
    // baseline of zero. Check the population BEFORE the page loop and name the
    // cause, so a destroyed file can never pose as a measurement.
    let populated = db
        .profiles_page(&PageRequest {
            view: PurgatoryView::All,
            active_threshold: 0,
            scope: PlanScope::All,
            search: None,
            group_id: None,
            sort: PageSort::Id,
            ascending: true,
            offset: 0,
            limit: 1,
        })
        .await
        .map(|page| page.total)
        .unwrap_or(0);
    if populated == 0 {
        println!(
            "ABORT flow_cost_contention: {path} holds no rows.\n\
             It was most likely wiped — `Database::open` drops and rebuilds a file whose\n\
             PRAGMA user_version != the schema tag, so a concurrent open destroyed it.\n\
             Re-copy from a QUIESCENT data.db, verify pragma_user_version, and run ONE\n\
             lab process at a time. Never point this env var at anything but a\n\
             disposable copy."
        );
        return;
    }
    println!("feed: {populated} endpoints");

    // A REAL group id, so the group-link family upserts rows that already exist
    // instead of inventing membership the feed does not have.
    let group_id = db
        .get_all_groups()
        .await
        .expect("groups")
        .into_iter()
        .next()
        .map(|g| g.id);

    // Real rows, pinned in ID order — an order no write can move, so every
    // repetition and every writer replays the same slice.
    //
    // The slice is BOUNDED to `want_links` and the four families are kept
    // consistent with it, because the production reference is one ~500-URL
    // batch (~2,500 rows across the four families). An unbounded slice makes
    // "one import transaction" a ~154,000-row write, which is neither the
    // production shape nor the import-upsert task's reference — and it measures
    // statement-building CPU rather than the write path.
    let want_links = (import_tx * links_per_tx).max(trickle_rows);
    let want_ips = geo_flush * rows_per_flush;
    let mut slice = ImportBatch::default();
    let mut geo: Vec<(leas_db::models::EndpointId, std::net::IpAddr, String)> = Vec::new();
    let mut offset = 0usize;
    // Links are the bound. Geo is collected opportunistically over the same walk
    // and truncated separately — letting the geo requirement drive the paging
    // is what produced an unbounded slice, since stored countries are sparse.
    'walk: while slice.len() < want_links {
        let request = PageRequest {
            view: PurgatoryView::All,
            active_threshold: 0,
            scope: PlanScope::All,
            search: None,
            group_id: None,
            sort: PageSort::Id,
            ascending: true,
            offset,
            limit: PROFILES_PAGE_SIZE,
        };
        let ids = db.profiles_page(&request).await.expect("page").ids;
        if ids.is_empty() {
            break;
        }
        let rows = db.load_page_rows(&ids, false).await.expect("rows");
        let resolutions = db.endpoint_resolutions(&ids).await.expect("resolutions");
        for row in &rows {
            if slice.len() >= want_links {
                break 'walk;
            }
            // One endpoint = one consistent unit across all four families, so
            // truncating the link budget can never orphan a protocol or a group
            // link from its endpoint.
            slice.endpoints.push(row.endpoint.clone());
            for protocol in row.protocols.values() {
                slice.protocols.push(protocol.clone());
            }
            for link in &row.links {
                if let Some(gid) = &group_id {
                    slice.group_links.push(leas_db::models::EndpointGroup {
                        endpoint_id: row.endpoint.id,
                        group_id: gid.clone(),
                        last_seen_at: link.last_seen_at,
                        sort_order: None,
                        endpoint: toasty::Deferred::default(),
                        group: toasty::Deferred::default(),
                    });
                }
            }
            slice.links.extend(row.links.iter().cloned());
            if geo.len() < want_ips
                && let Some(addrs) = resolutions.get(&row.endpoint.id)
            {
                for (ip, country) in addrs {
                    if let Some(iso) = country {
                        geo.push((row.endpoint.id, *ip, iso.clone()));
                    }
                }
            }
        }
        offset += PROFILES_PAGE_SIZE;
    }
    geo.truncate(want_ips);
    if geo.len() < want_ips {
        println!(
            "note: only {} of {want_ips} address rows carry a country in the walked slice; the geo rows use what exists",
            geo.len()
        );
    }
    println!(
        "slice: {} links, {} endpoints, {} protocols, {} group links, {} address rows (group {:?})",
        slice.links.len(),
        slice.endpoints.len(),
        slice.protocols.len(),
        slice.group_links.len(),
        geo.len(),
        group_id,
    );
    if slice.is_empty() {
        println!("SKIP flow_cost_contention: measure db has no links to replay");
        return;
    }

    let mut out: Vec<TableRow> = Vec::new();
    let mut failures = 0usize;
    let mut arm_import = ArmFailures::new("seq import tx");
    let mut arm_geo_batch = ArmFailures::new("seq geo flush BATCHED");
    let mut arm_geo_solo = ArmFailures::new("seq geo PER-ADDRESS (pre-fix)");
    let mut arm_geo_fan = ArmFailures::new("fan-in geo PER-ADDRESS");
    let mut arm_mix = ArmFailures::new("fan-in import+geo");

    // Hoisted out of every timed region: cloning the slice once per writer per
    // repetition would rival the collision this row exists to quantify.
    let slice = Arc::new(slice);
    let geo = Arc::new(geo);
    // One transaction == one production-shaped batch (~`links_per_tx` links and
    // the endpoint/protocol/group rows that belong to them), NOT the whole slice.
    let batches: Vec<Arc<ImportBatch>> = split_batches(&slice, import_tx, links_per_tx)
        .into_iter()
        .map(Arc::new)
        .collect();
    let families = format!(
        "{}ep/{}proto/{}gl per tx",
        batches.first().map_or(0, |b| b.endpoints.len()),
        batches.first().map_or(0, |b| b.protocols.len()),
        batches.first().map_or(0, |b| b.group_links.len()),
    );

    // 1. sequential import transaction
    let mut acc = Acc::new();
    for _ in 0..reps {
        for batch in &batches {
            let started = Instant::now();
            let r = write_import_once(Arc::clone(&db), Arc::clone(batch)).await;
            acc.add(started.elapsed());
            failures += usize::from(r.is_err());
            arm_import.record(r.is_ok());
        }
    }
    if !arm_import.report() {
        out.push(acc.row(&format!("seq import tx (4 families {families})"), 1.0));
    }

    // 2. sequential geo flush — skipped, not fatal, when no country is stored
    let mut acc = Acc::new();
    for _ in 0..reps {
        for rows in geo.chunks(rows_per_flush) {
            let started = Instant::now();
            let r = db.set_endpoint_ip_countries(rows).await;
            acc.add(started.elapsed());
            failures += usize::from(r.is_err());
            arm_geo_batch.record(r.is_ok());
        }
    }
    if geo.is_empty() {
        println!("note: no persisted country rows; the geo rows are not meaningful");
    } else {
        if !arm_geo_batch.report() {
            out.push(acc.row(
                &format!("seq geo flush BATCHED ({rows_per_flush} rows)"),
                1.0,
            ));
        }
    }

    // 2b. **Pre-fix** geo arm: the PER-ADDRESS writer `enrich.rs:444` used and
    // that T7 replaces. The batched row above is already the FIXED writer, so
    // without this arm the lab would measure only healthy code and T7 would have
    // no before. Small N on purpose: production ran p99 ~1,051 ms per address,
    // so 20 rows is already a multi-second measurement.
    let geo_singular = env_usize("LEAS_MEASURE_GEO_SINGULAR_ROWS", 20);
    if geo_singular > 0 && !geo.is_empty() {
        let take = geo_singular.min(geo.len());
        let mut acc = Acc::new();
        for (endpoint_id, ip, iso) in geo.iter().take(take) {
            let started = Instant::now();
            let r = db.set_endpoint_ip_country(*endpoint_id, *ip, iso).await;
            acc.add(started.elapsed());
            failures += usize::from(r.is_err());
            arm_geo_solo.record(r.is_ok());
        }
        if !arm_geo_solo.report() {
            out.push(acc.row("seq geo PER-ADDRESS (pre-fix writer)", 1.0));
        }
    }

    // 2c. **Pre-fix writer, CONCURRENTLY** — the arm that can actually reach the
    // failure regime. Aborts scale with the number of *concurrent* transactions,
    // not with the number of rows: 2b awaits one `set_endpoint_ip_country` at a
    // time, so it is a single writer and can never collide, and row 3 fans out
    // the BATCHED writer, which opens one transaction per flush. Production's
    // 88 `snapshot is stale` aborts and 10 `busy_timeout` drops came from ~1,000
    // overlapping single-row write transactions — this is the only row that
    // recreates that shape, and therefore the only one T12's WAL-vs-MVCC
    // decision can be read against.
    let geo_fanin = env_usize("LEAS_MEASURE_GEO_FANIN_TASKS", 16).max(1);
    if geo_singular > 0 && !geo.is_empty() {
        let take = geo_singular.min(geo.len());
        let rows: Vec<_> = geo.iter().take(take).cloned().collect();
        let mut acc = Acc::new();
        for _ in 0..reps {
            let started = Instant::now();
            let mut set = tokio::task::JoinSet::new();
            for shard in rows.chunks(rows.len().div_ceil(geo_fanin).max(1)) {
                let db = Arc::clone(&db);
                let shard = shard.to_vec();
                set.spawn(async move {
                    let mut local = 0usize;
                    for (endpoint_id, ip, iso) in &shard {
                        local += usize::from(
                            db.set_endpoint_ip_country(*endpoint_id, *ip, iso)
                                .await
                                .is_err(),
                        );
                    }
                    local
                });
            }
            let before = failures;
            while let Some(joined) = set.join_next().await {
                failures += joined.unwrap_or(0);
            }
            arm_geo_fan.samples += rows.len();
            arm_geo_fan.failures += failures - before;
            acc.add(started.elapsed());
        }
        if !arm_geo_fan.report() {
            out.push(acc.row(
                &format!("fan-in geo PER-ADDRESS / {geo_fanin} writers (pre-fix)"),
                1.0,
            ));
        }
    }

    // ── AFTER-NUMBERS, RowCache write-behind (2026-10-05, commit 9bf0232) ──
    //
    // Measured on a synthetic WAL feed (`flow_cost_seed_measure_db`, 74,014
    // endpoints x 1 protocol, default knobs: 5 reps, 8x800-link import tx, 16
    // geo flushes of 100 rows, 16 fan-in writers):
    //
    //   seq geo flush BATCHED (100 rows)           3,846,600 ns   80 samples
    //   seq geo PER-ADDRESS (pre-fix writer)          129,101 ns   20 samples
    //   fan-in geo PER-ADDRESS / 16 writers          3,576,034 ns    5 samples, 0/100 writes failed
    //   flush trickle WALL (4028 rows @ 12/s)  -> 32 flushes = 125.9 rows/flush, 0 staged left
    //
    // **What the migration changed: the commit COUNT.** Read the arms apart, because
    // only some of them exercise the driver:
    //   - Arm 2c, "fan-in geo PER-ADDRESS / 16 writers" (ABOVE this block, the row
    //     `fan-in geo PER-ADDRESS / {geo_fanin} writers (pre-fix)`), ran 16
    //     concurrent writers with **0/100 writes failed and zero `snapshot is
    //     stale` / `database is locked`**, against the 2026-10-01 production run's
    //     88 `snapshot is stale` aborts and 10 `busy_timeout` drops against ~1,000
    //     overlapping single-row write transactions. **Be careful what that
    //     proves**: arm 2c calls `db.set_endpoint_ip_country`, the PER-ADDRESS
    //     writer this plan does NOT touch — it is deliberately kept as the
    //     pre-fix control, so a clean run there is evidence that the ENGINE is no
    //     longer losing writes under this feed's concurrency, NOT evidence that
    //     `WriteBehind<CountrySpec>` fixed anything. The driver's own evidence is
    //     the "flush commits for the link writer" bullet below, the only figure in
    //     this block measured THROUGH the driver.
    //   - The arm physically below (block 3, `fan-in: import and geo writers
    //     OVERLAPPING`) is the mixed import+geo shape, and it is unusable — see
    //     its own paragraph at the end of this block.
    //   - flush commits for the link writer: 32 commits for 4,028 arrivals
    //     (125.9 rows/commit) at the production trickle rate, versus the ~8 the
    //     512-row size trigger alone would give for the same 4,028 rows staged
    //     in a tight loop, and versus 1,167 on the pre-driver trickle. The gain
    //     is the `TIMER_FLOOR_DIVISOR` floor: a bare tick waits for
    //     `flush_rows / 4` staged rows instead of committing whatever one row
    //     arrived.
    //   - `0 staged left` after the final flush: the driver drains rather than
    //     truncating, so the loss window closes on shutdown.
    //
    // **The retired per-row writer, for the A/B.** `apply_link_patches` used to
    // be one existence probe + one `UPDATE` per row (turso has no
    // `UPDATE ... FROM (VALUES ...)`, database.rs:1122). Measured over the
    // reference feed on a 512-patch window including the rank refresh:
    // **29.0 ms -> 10.0 ms** once it became one multi-row upsert per 400-row
    // chunk (ADR 0002 amendment 4; `docs/aegis/specs/2026-09-16-db-claim-verification.md:25`).
    // The neighbouring 11.1 / 10.6 / 10.6 ms figures are the STATEMENT-WIDTH
    // probe at 400 / 1,000 / 2,000 rows per statement, not this window. That
    // number is per-WINDOW and predates the driver; the driver's contribution is
    // the "flush commits for the link writer" count quoted above, not the
    // statement cost.
    //
    // **The import half of the mixed fan-in arm below could NOT be measured.**
    // `write_import_once` calls `upsert_protocols_bulk`, which rejects a
    // `Protocol` whose deferred `config` was not loaded ("deferred config not
    // loaded"). The slice is built from `load_page_rows`, which stopped
    // issuing `.include()` in fcf2a5f ("no toasty .include() on the profiles
    // read path") — a commit that is an ANCESTOR of this plan's base (a8c3019),
    // so the arm was already broken before the migration and the plan changed
    // nothing on that path (the diff touches no `upsert_*_bulk`). Every import
    // transaction therefore errors deterministically, `ArmFailures` correctly
    // DISCARDs both import rows, and the 680 `write failures` this run prints are
    // all that one cause. **The mixed fan-in arm produces NO row**, so this is
    // NOT the contention evidence: the geo arms (arm 2c above, arm 2) and the
    // driver-backed trickle row below carry the measurement instead. The mixed
    // arm stays unusable until the slice is rebuilt with protocol `config`
    // loaded.

    // 3. fan-in: import and geo writers OVERLAPPING, the production shape.
    // `batches` is shared, not moved: the closure captures it by reference, so a
    // second repetition would otherwise find it gone.
    let batches = Arc::new(batches);
    let mut acc = Acc::new();
    for _ in 0..reps {
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..fanin {
            let db = Arc::clone(&db);
            let batches = Arc::clone(&batches);
            let geo = Arc::clone(&geo);
            set.spawn(async move {
                let mut local = 0usize;
                for batch in batches.iter() {
                    local += usize::from(
                        write_import_once(Arc::clone(&db), Arc::clone(batch))
                            .await
                            .is_err(),
                    );
                }
                for rows in geo.chunks(rows_per_flush) {
                    local += usize::from(db.set_endpoint_ip_countries(rows).await.is_err());
                }
                local
            });
        }
        // Samples are counted UNCONDITIONALLY. Counting them only on a clean
        // round made any arm with one failure report "NO SAMPLES" and drop the
        // row — losing the measurement exactly when a partial failure is the
        // interesting result.
        arm_mix.samples += fanin * batches.len();
        let before = failures;
        while let Some(joined) = set.join_next().await {
            failures += joined.unwrap_or(0);
        }
        arm_mix.failures += failures - before;
        acc.add(started.elapsed());
    }
    if !arm_mix.report() {
        out.push(acc.row(&format!("fan-in import+geo mix / {fanin} writers"), 1.0));
    }

    // 4. link-writer flush on a wall-clock ARRIVAL schedule. The metric is
    // rows-per-flush, and arrival rate is what sets it.
    if slice.links.len() >= 2 {
        let writer = leas_db::WriteBehind::<leas_db::LinkSpec>::new(
            Arc::clone(&db),
            leas_db::write_behind::DEFAULT_FLUSH_ROWS,
            leas_db::write_behind::DEFAULT_FLUSH_INTERVAL,
        );
        let task = writer.spawn_flush_task();
        let arrivals: Vec<ProfileStats> = slice.links.iter().take(trickle_rows).cloned().collect();
        let gap = Duration::from_secs_f64(1.0 / trickle_rps as f64);
        let schedule_started = Instant::now();
        for link in &arrivals {
            writer.stage(link, leas_db::LinkGroups::RESULT);
            tokio::time::sleep(gap).await;
        }
        let drain_deadline = Instant::now() + Duration::from_secs(30);
        while writer.staged_len() > 0 && Instant::now() < drain_deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // Drain what the 30 s deadline left, BEFORE aborting: aborting mid-flush
        // can leave a partially-written window in a file the next run re-opens.
        if writer.staged_len() > 0 {
            writer.flush().await.expect("final trickle flush");
        }
        let flushes = writer.flush_count();
        let elapsed = schedule_started.elapsed();
        let staged_left = writer.staged_len();
        task.abort();
        if staged_left > 0 {
            println!(
                "  arm {:<44} {staged_left} rows still staged after the final flush — DISCARD",
                "flush trickle"
            );
        }
        let n = arrivals.len();
        out.push(TableRow {
            // ns here is the ARRIVAL-SCHEDULE wall (the sum of the sleeps), NOT a
            // per-flush cost. `n` carries the flush count, and the ratio printed
            // below is the number this row exists for.
            name: format!("flush trickle WALL ({n} rows @ {trickle_rps}/s) -> flushes"),
            ns: elapsed.as_nanos() as f64,
            n: u32::try_from(flushes).unwrap_or(u32::MAX),
        });
        println!(
            "\nlink writer: {n} arrivals @ {trickle_rps}/s over {elapsed:?} -> {flushes} flushes ({:.2} rows/flush, {staged_left} staged left)",
            n as f64 / flushes.max(1) as f64,
        );
    }

    print_table("contention: import + geo + link-writer mix", &out);
    println!("\nwrite failures: {failures}");
}

/// Seed `LEAS_MEASURE_DB` with a synthetic feed of `LEAS_MEASURE_SEED`
/// endpoints, so `flow_cost_contention` can be run against a WAL database and
/// against an MVCC one **without touching a real feed**.
///
/// MVCC needs a FRESH file created with `LEAS_TURSO_CONCURRENT_WRITES=1`:
/// an existing file keeps its `read_version` and stays WAL. So the two arms are
/// seeded separately, each into a file that does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "perf lab: run explicitly with --ignored"]
async fn flow_cost_seed_measure_db() {
    let Ok(path) = std::env::var("LEAS_MEASURE_DB") else {
        println!("SKIP flow_cost_seed_measure_db: set LEAS_MEASURE_DB");
        return;
    };
    let n = env_usize("LEAS_MEASURE_SEED", 74_014);
    // PROTOCOLS PER ENDPOINT, not a total: `synth_rows` is (endpoints,
    // protocols-per-endpoint), so passing a total here would ask for
    // endpoints x protocols rows and never finish.
    let protos_per_endpoint = env_usize("LEAS_MEASURE_SEED_PROTOS", 1);
    let mut state = test_state(Vec::new()).await;
    state.db = Arc::new(leas_db::Database::open(&path).await.expect("open seed db"));
    let rows = synth_rows(n, protos_per_endpoint);
    seed_db(&mut state, &rows).await;
    // Address rows too. Without them the contention mix skips its geo half
    // entirely ("no persisted country rows") — and the geo writer is the one
    // that produced the 2026-10-01 contention, so an A/B without it would
    // measure only the import arm.
    let addrs: Vec<(leas_db::models::EndpointId, std::net::IpAddr, String)> = (1..=n as i64)
        .map(|i| {
            (
                leas_db::models::EndpointId::new(i),
                std::net::IpAddr::from([
                    10,
                    (i / 65536) as u8,
                    ((i / 256) % 256) as u8,
                    (i % 256) as u8,
                ]),
                "ZZ".to_owned(),
            )
        })
        .collect();
    state
        .db
        .set_endpoint_ip_countries(&addrs)
        .await
        .expect("address rows");
    println!(
        "seeded {path}: {n} endpoints x {protos_per_endpoint} protocols, journal mode {}",
        if state.db.uses_concurrent_writes() {
            "MVCC"
        } else {
            "WAL"
        },
    );
}

/// Time the per-row `upsert_protocols_bulk` against its multi-row sibling's
/// scale. `upsert_protocols_bulk` is still ONE TYPED UPSERT PER ROW — the third
/// import family T6 deliberately deferred — so this is the cost of the writer
/// that no journal mode can make fast.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "perf lab: run explicitly with --ignored"]
async fn flow_cost_protocol_writer_cost() {
    let n = env_usize("LEAS_MEASURE_SEED_PROTOS", 200);
    let state = test_state(Vec::new()).await;
    let rows = synth_rows(n, n);
    let protocols: Vec<leas_db::models::Protocol> = rows
        .iter()
        .flat_map(|r| r.protocols.values().cloned())
        .collect();
    println!("probing {} protocols", protocols.len());
    let started = Instant::now();
    let mut conn = state.db.connection().await.expect("conn");
    let mut tx = conn.transaction().await.expect("tx");
    leas_db::upsert_protocols_bulk(&mut tx, &protocols)
        .await
        .expect("protocols");
    tx.commit().await.expect("commit");
    let elapsed = started.elapsed();
    let rows = protocols.len().max(1);
    println!(
        "upsert_protocols_bulk (PER ROW): {rows} protocols in {elapsed:?} = {:.1} us/row",
        elapsed.as_secs_f64() * 1e6 / rows as f64,
    );
}
