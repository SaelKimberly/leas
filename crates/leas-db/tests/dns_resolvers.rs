//! DNS source/resolver persistence: uniqueness by stamp, a refresh that never
//! costs a retest, the pool query, and the unique source URL.
//!
//! Spec: `docs/aegis/specs/2026-11-20-dns-resolvers-design.md` D3–D5.

use leas_db::Database;
use leas_db::database::DnsCandidateRow;
use leas_db::models::{DnsSource, GroupStatus, ResolverStatus};

fn source(id: &str, url: &str) -> DnsSource {
    DnsSource {
        id: id.to_string(),
        name: Some(id.to_string()),
        url: url.to_string(),
        enabled: true,
        user_agent: None,
        sort_order: Some(0),
        last_refreshed: None,
        status: Some(GroupStatus::Never),
        error_message: None,
        refresh_interval: Some(1440),
    }
}

fn candidate(stamp: &str) -> DnsCandidateRow {
    DnsCandidateRow {
        stamp: stamp.to_string(),
        protocol: "dnscrypt".to_string(),
        host: "94.140.14.140".to_string(),
        port: 5443,
    }
}

async fn seeded() -> Database {
    let db = Database::in_memory().await.expect("in-memory db");
    assert!(
        db.seed_dns_source_if_empty(&source("s1", "https://example.com/list"))
            .await
            .expect("seed")
    );
    db
}

#[tokio::test]
async fn pool_orders_by_latency_and_respects_enabled() {
    let db = seeded().await;
    // The seed is idempotent: a second call on a non-empty table inserts
    // nothing, so the built-in list cannot come back after the user's own.
    assert!(
        !db.seed_dns_source_if_empty(&source("s2", "https://other.example/list"))
            .await
            .expect("second seed")
    );

    db.refresh_source_links("s1", &[candidate("a"), candidate("b"), candidate("c")])
        .await
        .expect("refresh");
    db.apply_dns_test_results(&[
        ("a".to_string(), Some(30), None),
        ("b".to_string(), Some(10), None),
        ("c".to_string(), None, Some("timed out".to_string())),
    ])
    .await
    .expect("results");

    let pool: Vec<String> = db
        .dns_pool(10)
        .await
        .expect("pool")
        .into_iter()
        .map(|row| row.stamp)
        .collect();
    assert_eq!(pool, ["b", "a"], "fastest first, a failure is excluded");
    assert_eq!(db.dns_pool(1).await.expect("limit 1").len(), 1);

    db.set_dns_resolver_enabled("b", false)
        .await
        .expect("disable");
    let pool: Vec<String> = db
        .dns_pool(10)
        .await
        .expect("pool")
        .into_iter()
        .map(|row| row.stamp)
        .collect();
    assert_eq!(pool, ["a"], "a disabled resolver leaves the pool");

    let all = db.list_dns_resolvers().await.expect("rows");
    assert_eq!(all.len(), 3, "a failure stays listed");
    let failed = all.iter().find(|row| row.stamp == "c").expect("failed row");
    assert_eq!(failed.status, ResolverStatus::Error);
    assert_eq!(failed.error.as_deref(), Some("timed out"));
    assert_eq!(failed.latency_ms, None);
}

#[tokio::test]
async fn one_stamp_in_two_sources_is_one_row_and_survives_a_delete() {
    let db = seeded().await;
    db.upsert_dns_source(&source("s2", "https://other.example/list"))
        .await
        .expect("second source");

    db.refresh_source_links("s1", &[candidate("shared"), candidate("only1")])
        .await
        .expect("refresh s1");
    db.refresh_source_links("s2", &[candidate("shared"), candidate("only2")])
        .await
        .expect("refresh s2");
    assert_eq!(
        db.list_dns_resolvers().await.expect("rows").len(),
        3,
        "the shared stamp is one row"
    );

    db.apply_dns_test_results(&[("shared".to_string(), Some(7), None)])
        .await
        .expect("measure shared");

    db.delete_dns_source("s1").await.expect("delete s1");
    let rows = db.list_dns_resolvers().await.expect("rows");
    let stamps: Vec<&str> = rows.iter().map(|row| row.stamp.as_str()).collect();
    assert!(stamps.contains(&"shared"), "still listed by s2");
    assert!(stamps.contains(&"only2"));
    assert!(!stamps.contains(&"only1"), "s1's own resolver is gone");
    assert_eq!(
        rows.iter()
            .find(|row| row.stamp == "shared")
            .expect("shared")
            .latency_ms,
        Some(7),
        "deleting a source must not erase the other source's measurement"
    );

    db.delete_dns_source("s2").await.expect("delete s2");
    assert!(
        db.list_dns_resolvers().await.expect("rows").is_empty(),
        "the last link takes the row"
    );
}

#[tokio::test]
async fn refresh_preserves_a_measurement() {
    let db = seeded().await;
    db.refresh_source_links("s1", &[candidate("a")])
        .await
        .expect("refresh");
    db.apply_dns_test_results(&[("a".to_string(), Some(42), None)])
        .await
        .expect("measure");
    let before = db.list_dns_resolvers().await.expect("rows").remove(0);
    db.set_dns_resolver_enabled("a", false)
        .await
        .expect("disable");

    // An unchanged refresh must be a no-op for every measurement column.
    db.refresh_source_links("s1", &[candidate("a")])
        .await
        .expect("refresh again");
    let after = db.list_dns_resolvers().await.expect("rows").remove(0);
    assert_eq!(after.latency_ms, Some(42));
    assert_eq!(after.checked_at, before.checked_at);
    assert_eq!(after.status, ResolverStatus::Ok);
    assert!(!after.enabled, "a user's disable survives a refresh");
}

#[tokio::test]
async fn duplicate_source_url_is_refused() {
    let db = seeded().await;
    let err = db
        .upsert_dns_source(&source("s2", "https://example.com/list"))
        .await
        .expect_err("the unique index must refuse a second row for one URL");
    assert!(
        err.to_string().to_lowercase().contains("unique"),
        "the failure names the constraint: {err}"
    );
}

#[tokio::test]
async fn a_refresh_for_a_deleted_source_writes_nothing() {
    let db = seeded().await;
    db.refresh_source_links("s1", &[candidate("a")])
        .await
        .expect("refresh");
    db.delete_dns_source("s1").await.expect("delete");
    // The fetch may still be in flight when the user deletes the source; the
    // late write must not re-create it or leave a dangling link.
    db.refresh_source_links("s1", &[candidate("a")])
        .await
        .expect("late refresh");
    assert!(db.list_dns_resolvers().await.expect("rows").is_empty());
    assert!(db.list_dns_sources().await.expect("sources").is_empty());
}

#[tokio::test]
async fn a_refresh_updates_a_changed_endpoint_and_keeps_the_measurement() {
    let db = seeded().await;
    db.refresh_source_links("s1", &[candidate("a")])
        .await
        .expect("refresh");
    db.apply_dns_test_results(&[("a".to_string(), Some(5), None)])
        .await
        .expect("measure");
    let mut changed = candidate("a");
    changed.protocol = "doh".to_string();
    changed.host = "dns.example".to_string();
    changed.port = 443;
    db.refresh_source_links("s1", &[changed])
        .await
        .expect("refresh");
    let row = db.list_dns_resolvers().await.expect("rows").remove(0);
    assert_eq!(row.protocol, "doh");
    assert_eq!(row.host, "dns.example");
    assert_eq!(row.port, 443);
    assert_eq!(
        row.latency_ms,
        Some(5),
        "the endpoint moved; the measurement did not"
    );
}
