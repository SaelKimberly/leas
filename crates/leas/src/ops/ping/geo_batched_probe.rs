//! Production-shape geo A/B: the batched writer `set_endpoint_ip_countries`
//! (enrich.rs:789) under fan-in, which `flow_cost_contention` never measures —
//! its fan-in arm 2c is the retired PER-ADDRESS control ("the pre-fix control
//!
//! The probe exists because that control and the retired-writer numbers it
//! produces are the shape that once made MVCC look 24.6× faster than WAL;
//! measuring through the *production* batched writer inverts it. Kept as a
//! permanent lab so the claim never goes unmeasured again.
//!
//! ```text
//! cargo test -p leas --release --lib --features perf-lab -- --ignored --nocapture geo_batched_fanin_probe
//! ```
//!
//! Knobs (all optional):
//!   `LEAS_MEASURE_DB`        fixture path (required)
//!   `LEAS_GEOB_FANIN`        concurrent writer tasks (default 16)
//!   `LEAS_GEOB_FLUSHES`      batches per writer (default 16)
//!   `LEAS_GEOB_ROWS`         addresses per batch (default 100)
//!   `LEAS_GEOB_REPS`         timed repetitions (default 3)
//!   `LEAS_GEOB_SHARED`       1 = same endpoint ids across writers (synthetic
//!                            contention); 0 = disjoint blocks (production shape)
//!
//! MVCC arms need a file seeded with `LEAS_TURSO_CONCURRENT_WRITES=1` (an
//! existing file keeps its journal mode), the same rule as `flow_cost_seed_measure_db`.

use std::sync::Arc;
use std::time::Instant;

use leas_db::Database;
use leas_db::models::EndpointId;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "perf lab: run explicitly with --ignored"]
async fn geo_batched_fanin_probe() {
    let Ok(path) = std::env::var("LEAS_MEASURE_DB") else {
        println!("SKIP: set LEAS_MEASURE_DB=<fixture>");
        return;
    };
    let fanin = env_usize("LEAS_GEOB_FANIN", 16).max(1);
    let flushes = env_usize("LEAS_GEOB_FLUSHES", 16);
    let rows = env_usize("LEAS_GEOB_ROWS", 100);
    let reps = env_usize("LEAS_GEOB_REPS", 3);
    // 1 = all writers hit the SAME endpoint ids (the contention shape);
    // 0 = disjoint blocks (the throughput shape).
    let shared = env_usize("LEAS_GEOB_SHARED", 1) == 1;

    let db = Arc::new(Database::open(&path).await.expect("open"));
    println!(
        "\n== geo batched fan-in: {} | journal {} | fanin {} | {}x{} rows x{} reps | shared={} ==",
        path,
        if db.uses_concurrent_writes() {
            "MVCC"
        } else {
            "WAL"
        },
        fanin,
        flushes,
        rows,
        reps,
        shared,
    );

    let (ok, failed) = (
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    );
    let mut samples: Vec<u128> = Vec::new();
    for _ in 0..reps {
        // Each writer owns `flushes` batches of `rows` address writes.
        // Each writer owns `flushes` batches of `rows` address writes,
        // so `batches` is one Batch PER (writer, flush), flat.
        type Batch = Vec<(EndpointId, std::net::IpAddr, String)>;
        let batches: Vec<Batch> = (0..fanin)
            .flat_map(|w| {
                (0..flushes).map(move |f| {
                    (0..rows)
                        .map(|i| {
                            // Same ids across writers when shared (contention);
                            // distinct blocks otherwise (throughput).
                            let id = if shared {
                                (i % 512) as i64 + 1
                            } else {
                                ((w * flushes + f) * rows + i) as i64 + 1
                            };
                            (
                                EndpointId::new(id),
                                std::net::IpAddr::from([
                                    10u8,
                                    0,
                                    (id / 256) as u8,
                                    (id % 256) as u8,
                                ]),
                                format!("C{w}"),
                            )
                        })
                        .collect::<Batch>()
                })
            })
            .collect();

        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for writer_batches in batches.chunks(fanin.max(1)) {
            let owned: Vec<Batch> = writer_batches.to_vec();
            let db = Arc::clone(&db);
            let ok = Arc::clone(&ok);
            let failed = Arc::clone(&failed);
            set.spawn(async move {
                for batch in owned {
                    match db.set_endpoint_ip_countries(&batch).await {
                        Ok(()) => {
                            ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(e) => {
                            failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            eprintln!("write failed: {e}");
                        }
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
        samples.push(started.elapsed().as_nanos());
    }

    samples.sort_unstable();
    let med = samples[samples.len() / 2];
    // One sample == fanin x flushes batched writes.
    let per_batch = med / (fanin * flushes) as u128;
    println!(
        "fan-in geo BATCHED / {fanin} writers: median wall {med} ns over {fanin}x{flushes} batches x{reps} reps = {per_batch} ns/batch | ok={} failed={}",
        ok.load(std::sync::atomic::Ordering::Relaxed),
        failed.load(std::sync::atomic::Ordering::Relaxed),
    );
    println!("samples: {samples:?}");
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
