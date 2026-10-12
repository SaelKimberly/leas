//! Headless reproduction of the subscription-update path against the real
//! 7000+ URL feed. #[ignore]d by default (needs network); run with:
//!   cargo test -p leas --test `e2e_real_feed` -- --ignored --nocapture
use std::sync::Arc;
use std::time::Instant;

use leas_config::import_export::ValidationSettings;

const FEED: &str = "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/RU_Best/ru_white_all_WHITE.txt";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "network + real feed"]
async fn streaming_import_real_feed_completes() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
    let validation = ValidationSettings::default();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let t0 = Instant::now();
    let resp = client.get(FEED).send().await.unwrap();
    let t_fetch = t0.elapsed();
    assert!(
        resp.status().is_success(),
        "fetch failed: {}",
        resp.status()
    );

    let outcome = leas::ops::stream_import::import_http_subscription(
        FEED,
        "leas-e2e",
        &db,
        None,
        &validation,
        Default::default(),
    )
    .await;
    let t_all = t0.elapsed();
    assert!(
        outcome.ended_early.is_none(),
        "real feed ended early: {:?}",
        outcome.ended_early
    );
    let count = outcome.links;
    let summary = outcome.summary;
    println!(
        "links={count} errors={} fetch={t_fetch:?} total={t_all:?}",
        summary.total_errors
    );
    assert!(count > 5000, "expected thousands of links, got {count}");
    assert!(
        t_all.as_secs() < 600,
        "import took {t_all:?} — frozen-path regression"
    );
}
