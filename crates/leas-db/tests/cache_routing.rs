//! The driver fork's statement-cache routing (S0b).
//!
//! The leak this pins: the published driver ran EVERY statement through
//! `prepare_cached`, whose per-connection map is unbounded and keyed by SQL
//! text. The bulk writers inline their literals, so each window is a new text —
//! a compiled program retained for the connection's life (measured ~116-310 KiB
//! per distinct text; the page hydration grew RSS +123,580 KiB over 400 calls).
//!
//! The fork routes `Operation::RawSql` (hand-built, literal-inlined text — what
//! `toasty::sql::query`/`statement` produce) through the UNCACHED `prepare`, and
//! keeps `prepare_cached` only for engine-generated `Insert`/`QuerySql`. This
//! test drives the `RawSql` path with fresh text on ONE pooled connection and
//! asserts RSS does not scale with the call count.

use leas_db::Database;

/// Resident set size in KiB, from the kernel. The same probe the original leak
/// measurement used.
fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .expect("VmRSS is a number");
        }
    }
    panic!("VmRSS not found in /proc/self/status");
}

/// Fresh-text `RawSql` statements must NOT accumulate compiled programs.
///
/// 400 unique statements is the count the original leak was measured at
/// (+123,580 KiB then). With the `RawSql` arm on the uncached `prepare` the
/// growth is allocator churn only. The bound is deliberately loose — RSS is
/// noisy, and the point is a PLATEAU, not a precise number — but it separates
/// cleanly from the ~123 MiB the leak produced.
///
/// The statements are the PAGE-HYDRATION shape (the id-inlined read
/// `load_page_projection` issues): each iteration inlines a FRESH set of integer
/// ids, so the SQL text is unique and LONG — the configuration that produced the
/// measured +123,580 KiB over 400 calls (~309 KiB per compiled program). A tiny
/// synthetic `INSERT` does not discriminate (400 of them fit under any sane
/// bound), so the guard must use the real shape.
#[tokio::test]
async fn unique_raw_sql_texts_do_not_grow_the_statement_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::open(dir.path().join("cache.db"))
        .await
        .expect("open");
    let mut conn = db.connection().await.expect("conn");

    toasty::sql::statement("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)")
        .exec(&mut conn)
        .await
        .expect("create");
    for n in 0..2048 {
        toasty::sql::statement(format!("INSERT INTO t (id, v) VALUES ({n}, 'v{n}')"))
            .exec(&mut conn)
            .await
            .expect("seed");
    }

    // The page-projection shape: 200 ids inlined as integer literals, a fresh
    // set every call — exactly what made the cache grow per text.
    let projection = |base: i64| {
        let ids = (0..200)
            .map(|n| (base + n).to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "SELECT t.id, t.v, (SELECT ip.id FROM t ip WHERE ip.id = t.id LIMIT 1) \
             FROM t WHERE t.id IN ({ids})"
        )
    };

    // Warm up (the first statements compile + allocate), then measure.
    for n in 0..16 {
        toasty::sql::query(projection(n * 200))
            .exec(&mut conn)
            .await
            .expect("warm query");
    }
    let before = rss_kib();

    for n in 16..416 {
        toasty::sql::query(projection(n * 200))
            .exec(&mut conn)
            .await
            .expect("query");
    }

    let grew = rss_kib().saturating_sub(before);
    eprintln!("RawSql projection plateau: grew {grew} KiB over 400 unique texts");
    // Measured: the uncached routing grows 0 KiB here; the cached routing grows
    // 59,336 KiB (and +123,580 KiB at the page-hydration shape's text size). The
    // bound sits well inside that gap, and this binary runs ONE test, so the
    // process RSS is not polluted by parallel allocation.
    assert!(
        grew < 8 * 1024,
        "400 unique-text RawSql projections must PLATEAU (a cached routing grew 59,336 KiB at this \
         count, +123,580 KiB at the page-hydration shape); it grew {grew} KiB"
    );
}
