//! Mechanics of the raw-SQL Profiles page queries: paging, counting,
//! anchoring, link order, bind formatting, and a schema-drift guard.
//!
//! The ordering *parity* golden (SQL vs the Rust comparator) lives in the
//! `xray-tui` crate, where the comparators are.

use toasty::{Deferred, Json};
use xray_tui_db::Database;
use xray_tui_db::models::{
    Endpoint, EndpointId, EndpointIp, ErrorInfo, HostType, Latency, ProfileStats, Protocol,
    ProtocolId, PurgatoryView, Security, TrafficStats, Transport,
};
use xray_tui_db::profiles_query::{PageRequest, PageSort, PlanScope};
use xray_tui_db::{LinkGroups, LinkPatch};
use xray_tui_proto::proto_spec::common::TransportConfig;
use xray_tui_proto::proto_spec::{
    ProtocolConfig, ProtocolKind, SecurityConfig, SecurityType, TransportType, VlessConfig,
};

/// Epoch seconds — the storage unit of every timestamp column.
const fn ts(secs: i64) -> i64 {
    secs
}

const ALL_ENDPOINTS: [i64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

const ALL_SORTS: [PageSort; 4] = [PageSort::Test, PageSort::Port, PageSort::Ip, PageSort::Id];

const fn request(sort: PageSort, ascending: bool, offset: usize, limit: usize) -> PageRequest {
    PageRequest {
        view: PurgatoryView::All,
        active_threshold: ts(0),
        scope: PlanScope::All,
        search: None,
        group_id: None,
        sort,
        ascending,
        offset,
        limit,
    }
}

async fn seed_endpoint(
    conn: &mut toasty::Connection,
    id: i64,
    host_type: HostType,
    resolved: &[&str],
) {
    toasty::create!(Endpoint {
        created_at: 0,
        id: EndpointId::new(id),
        domain: Endpoint::derive_domain(&format!("h{id}.example"), host_type).0,
        sub_domain: Endpoint::derive_domain(&format!("h{id}.example"), host_type).1,
        port: 443,
        ports: Vec::<u16>::new(),
    })
    .exec(&mut *conn)
    .await
    .expect("create endpoint");
    // The address set is `endpoint_ip`'s: a DNS host with no rows is the
    // unresolved band's input, and a resolved one carries its addresses there.
    for ip in resolved {
        let key = xray_tui_db::endpoint_ip::key_of_str(ip).expect("a real address");
        toasty::create!(EndpointIp {
            endpoint_id: EndpointId::new(id),
            ip_key: key,
        })
        .exec(&mut *conn)
        .await
        .expect("create address");
    }
}

#[allow(clippy::too_many_arguments)]
async fn seed_link_with(
    conn: &mut toasty::Connection,
    endpoint_id: i64,
    protocol_id: i64,
    delay: Option<i64>,
    error_kind: Option<&str>,
    last_seen: i64,
    transport: TransportType,
) {
    toasty::create!(Protocol {
        created_at: 0,
        id: ProtocolId::new(protocol_id),
        sig: protocol_id,
        proto_kind: ProtocolKind::Vless,
        transport: Transport {
            r#type: transport,
            // Match the type: a row claiming `x_http` while its own config says
            // `tcp` is an inconsistency that only matters because every page and
            // rank path reads `type` and leaves this deferred carrier unloaded.
        },
        security: Security {
            r#type: SecurityType::None,
            sni: None,
            fp: None,
            insecure: None,
        },
        config: Deferred::from(Json(ProtocolConfig::Vless(VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        }))),
    })
    .exec(&mut *conn)
    .await
    .expect("create protocol");

    toasty::create!(ProfileStats {
        created_at: 0,
        updated_at: 0,
        protocol_id: ProtocolId::new(protocol_id),
        endpoint_id: EndpointId::new(endpoint_id),
        last_seen_at: ts(last_seen),
        stab_mask: 0,
        stab_len: 0,
        traffic: TrafficStats {
            today_up: 0,
            today_down: 0,
            total_up: 0,
            total_down: 0,
        },
    })
    .exec(&mut *conn)
    .await
    .expect("create link");

    if let Some(delay) = delay {
        // A real measurement IS a success (spec `2026-10-09-stab-bin-design`
        // §6.2): seed the one-sample ring so `rank_proven` follows, exactly as
        // the day-one seed does for a real database. Without this the fixture
        // would carry `latency='real'` with an empty ring — a state the law's
        // invariant (`rank_bin ∈ 0..=5 ⇒ proven`) forbids.
        toasty::sql::statement(
            "UPDATE profile_stats SET latency = 'real', latency_delay = ?1, \
             stab_mask = 1, stab_len = 1 \
             WHERE endpoint_id = ?2 AND protocol_id = ?3",
        )
        .bind(delay)
        .bind(endpoint_id)
        .bind(protocol_id)
        .exec(&mut *conn)
        .await
        .expect("set latency");
    }
    if let Some(kind) = error_kind {
        // `ErrorInfo.text` is a non-Option String: the flag without text breaks
        // every typed read of `profile_stats`.
        toasty::sql::statement(
            "UPDATE profile_stats SET error = 1, error_kind = ?1, error_text = ?4 \
             WHERE endpoint_id = ?2 AND protocol_id = ?3",
        )
        .bind(kind)
        .bind(endpoint_id)
        .bind(protocol_id)
        .bind(format!("{kind} probe"))
        .exec(&mut *conn)
        .await
        .expect("set error");
    }
}

/// The TCP fixture link most rows use.
async fn seed_link(
    conn: &mut toasty::Connection,
    endpoint_id: i64,
    protocol_id: i64,
    delay: Option<i64>,
    error_kind: Option<&str>,
    last_seen: i64,
) {
    seed_link_with(
        conn,
        endpoint_id,
        protocol_id,
        delay,
        error_kind,
        last_seen,
        TransportType::Tcp,
    )
    .await;
}

/// A `ProfileStats` value for the value-taking write paths (`upsert_link`,
/// `apply_link_patches`) — the seeded equivalent of a ping result.
fn link_value(
    endpoint_id: i64,
    protocol_id: i64,
    delay: Option<i32>,
    error_kind: Option<&str>,
    last_seen: i64,
) -> ProfileStats {
    ProfileStats {
        protocol_id: ProtocolId::new(protocol_id),
        endpoint_id: EndpointId::new(endpoint_id),
        last_used_at: None,
        last_seen_at: ts(last_seen),
        latency: delay.map(|delay| Latency::Real { delay, ip: None }),
        speed_bps: None,
        error: error_kind.map(|kind| ErrorInfo {
            kind: match kind {
                "real" => xray_tui_db::models::ProfileErr::Real,
                "fast" => xray_tui_db::models::ProfileErr::Fast,
                _ => xray_tui_db::models::ProfileErr::Name,
            },
            text: format!("{kind} probe"),
        }),
        purge_reason: None,
        // A real delay is a success (see `seed_link_with`): seed the ring so
        // the fixture obeys the law's proven invariant.
        stab_mask: i64::from(delay.is_some()),
        stab_len: i64::from(delay.is_some()),
        traffic: TrafficStats {
            today_up: 0,
            today_down: 0,
            total_up: 0,
            total_down: 0,
        },
        created_at: ts(last_seen),
        updated_at: ts(last_seen),
        version: 1,
        protocol: Deferred::default(),
        endpoint: Deferred::default(),
    }
}

/// Fixture: measured successes, both error bands, untested, DNS unresolved and
/// resolved, a manual override pointing away from the minimum-weight link, and
/// a measured link with an error marker beside an untested sibling.
async fn seed_fixture() -> Database {
    let db = Database::in_memory().await.expect("in-memory db");
    seed_into(&db).await;
    db
}

/// Seed the standard fixture into an EXISTING database (so a file-backed one
/// can exercise the direct reader path the in-memory tests fall back past).
async fn seed_into(db: &Database) {
    let mut conn = db.connection().await.expect("conn");

    // e1: real 30 + fast-error sibling
    seed_endpoint(&mut conn, 1, HostType::Dns, &["10.0.0.1"]).await;
    seed_link(&mut conn, 1, 101, Some(30), None, 100).await;
    seed_link(&mut conn, 1, 102, None, Some("fast"), 200).await;
    // e2: real 10
    seed_endpoint(&mut conn, 2, HostType::Dns, &["10.0.0.2"]).await;
    seed_link(&mut conn, 2, 103, Some(10), None, 150).await;
    // e3: untested
    seed_endpoint(&mut conn, 3, HostType::Dns, &["10.0.0.3"]).await;
    seed_link(&mut conn, 3, 104, None, None, 50).await;
    // e4: manual override away from the minimum-weight link
    seed_endpoint(&mut conn, 4, HostType::Dns, &["10.0.0.4"]).await;
    seed_link(&mut conn, 4, 105, Some(90), None, 120).await;
    seed_link(&mut conn, 4, 106, Some(500), None, 130).await;
    toasty::sql::statement("UPDATE endpoints SET manual_protocol_override = ?1 WHERE id = ?2")
        .bind(106_i64)
        .bind(4_i64)
        .exec(&mut conn)
        .await
        .expect("set override");
    // e5: measured link WITH an error marker beside an untested sibling
    seed_endpoint(&mut conn, 5, HostType::Dns, &["10.0.0.5"]).await;
    seed_link(&mut conn, 5, 107, Some(40), Some("fast"), 140).await;
    seed_link(&mut conn, 5, 108, None, None, 160).await;
    // e6: dns host, unresolved (persisted) despite a stored measurement.
    // Deliberately TCP while e7's representative is `x_http`: the two rows must
    // DISAGREE on weight (5 vs 7), because that disagreement is what makes the
    // parity golden red if a reader stops understanding toasty's `x_http` label.
    // Give e6 the same transport and both laws would agree again — which is how
    // a revert-proof test silently stops proving anything.
    seed_endpoint(&mut conn, 6, HostType::Dns, &[]).await;
    seed_link(&mut conn, 6, 109, Some(5), None, 170).await;
    // e8: the endpoint-level stability discriminator. It and e2 below are both
    // a single tcp link in bin 0 with the SAME static weight, and they differ
    // ONLY on the ring: e2 perfect, e8 poor. That makes their relative position
    // a pure function of the term order — with `rank_stab` before `rank_weight`
    // (the shipped law) e2 leads; swap the two terms and e8 leads, so the
    // parity golden goes red. Nothing else in the feed can discriminate the
    // two terms, because the weight only decides when bins and stability tie.
    seed_endpoint(&mut conn, 8, HostType::Dns, &["10.0.0.8"]).await;
    seed_link(&mut conn, 8, 113, Some(10), None, 210).await;
    toasty::sql::statement(
        "UPDATE profile_stats SET stab_mask = 0, stab_len = 4 \
         WHERE endpoint_id = 8 AND protocol_id = 113",
    )
    .exec(&mut conn)
    .await
    .expect("e8 ring: 0 of 4 (poor)");
    // e1's 101 (real 30, tcp, bin 0) is e8's true peer: same bin, same static
    // weight, opposite ring. e2 is left truthful because
    // `resolving_a_dns_host_moves_its_stored_key` anchors on that endpoint's
    // position relative to e7.
    toasty::sql::statement(
        "UPDATE profile_stats SET stab_mask = 15, stab_len = 4 \
         WHERE endpoint_id = 1 AND protocol_id = 101",
    )
    .exec(&mut conn)
    .await
    .expect("e1/101 ring: 4 of 4 (perfect)");

    // e7: dns host WITH a persisted resolution, plus a name-resolution failure
    seed_endpoint(&mut conn, 7, HostType::Dns, &["203.0.113.7"]).await;
    seed_link(&mut conn, 7, 110, Some(7), None, 180).await;
    seed_link(&mut conn, 7, 111, None, Some("name"), 190).await;
    // A link whose transport's STORED label is `x_http` — toasty's embed writes
    // the snake_case ident, not the wire spelling `xhttp`. `endpoint_rank::
    // refresh` reads that label as text, so a reader using `FromStr` (wire
    // spellings only) persists a ZERO weight for this link while every typed
    // path computes a real one, and the SQL page order then disagrees with the
    // in-memory comparator. The parity golden below is what notices.
    seed_link_with(&mut conn, 7, 112, Some(9), None, 200, TransportType::XHttp).await;
    drop(conn);

    // These fixtures write links with raw statements, bypassing the write
    // paths that keep `endpoint_rank` current (see the freshness test below).
    // Establish the same invariant they do, explicitly.
    let ids: Vec<EndpointId> = (1..=8).map(EndpointId::new).collect();
    db.refresh_endpoint_ranks(&ids).await.expect("seed ranks");
}

/// The direct turso reader must return the SAME page the toasty path does —
/// every sort, both directions, all three views. The file db takes the direct
/// path; the in-memory one falls back to toasty.
#[tokio::test]
async fn the_direct_page_matches_the_toasty_page() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_db = Database::open(dir.path().join("direct.db"))
        .await
        .expect("file db");
    assert!(
        file_db.uses_direct_reader(),
        "a file db has a direct reader"
    );
    seed_into(&file_db).await;
    let mem_db = seed_fixture().await;

    for sort in ALL_SORTS {
        for ascending in [true, false] {
            for view in [
                PurgatoryView::All,
                PurgatoryView::Active,
                PurgatoryView::Purgatory,
            ] {
                let req = PageRequest {
                    view,
                    ..request(sort, ascending, 0, 100)
                };
                let direct = file_db.profiles_page(&req).await.expect("direct page");
                let toasty = mem_db.profiles_page(&req).await.expect("toasty page");
                assert_eq!(
                    direct.ids, toasty.ids,
                    "direct vs toasty {sort:?} asc={ascending} view={view:?}"
                );
                assert_eq!(direct.total, toasty.total, "total {sort:?} {view:?}");
            }
        }
    }

    // The direct path binds params through `params_from_iter`; search (String
    // prefix + the `rank_addr` Bytes range) and group (a String bind) must
    // produce the SAME page as toasty, or a param-order/type mismatch ships to
    // the file-backed UI untested.
    for search in ["h1", "10.1", "443"] {
        let req = PageRequest {
            search: Some(search.to_string()),
            ..request(PageSort::Test, true, 0, 100)
        };
        let direct = file_db.profiles_page(&req).await.expect("direct search");
        let toasty = mem_db.profiles_page(&req).await.expect("toasty search");
        assert_eq!(direct.ids, toasty.ids, "direct vs toasty search={search}");
        assert_eq!(direct.total, toasty.total, "total search={search}");
    }
    // A group predicate binds a String id through the direct path. Both dbs
    // get the same membership; the ids must match.
    for db in [&file_db, &mem_db] {
        let mut conn = db.connection().await.expect("conn");
        for endpoint in [1_i64, 2] {
            toasty::create!(xray_tui_db::models::EndpointGroup {
                endpoint_id: EndpointId::new(endpoint),
                group_id: "g1".to_string(),
                last_seen_at: 0,
            })
            .exec(&mut conn)
            .await
            .expect("create group link");
        }
    }
    let req = PageRequest {
        group_id: Some("g1".to_string()),
        ..request(PageSort::Test, true, 0, 100)
    };
    let direct = file_db.profiles_page(&req).await.expect("direct group");
    let toasty = mem_db.profiles_page(&req).await.expect("toasty group");
    assert_eq!(direct.ids, toasty.ids, "direct vs toasty group");
    assert!(!direct.ids.is_empty(), "the group predicate selected rows");
}

#[tokio::test]
async fn paging_visits_every_endpoint_exactly_once() {
    let db = seed_fixture().await;
    for limit in [1_usize, 2, 3, 100] {
        let mut seen = Vec::new();
        let mut offset = 0;
        loop {
            let page = db
                .profiles_page(&request(PageSort::Test, true, offset, limit))
                .await
                .expect("page");
            assert_eq!(page.total, ALL_ENDPOINTS.len() as u64);
            if page.ids.is_empty() {
                break;
            }
            seen.extend(page.ids.iter().map(|id| id.get()));
            offset += limit;
        }
        let mut got = seen.clone();
        got.sort_unstable();
        assert_eq!(got, ALL_ENDPOINTS.to_vec(), "limit {limit}");
        assert_eq!(
            seen.len(),
            ALL_ENDPOINTS.len(),
            "no duplicates, limit {limit}"
        );
    }
}

/// The plan scopes select endpoints by their MATERIALIZED tier (ADR 0003), and
/// the page, the walk and the count agree at every scope — the batch plan and
/// its footer cannot drift.
#[tokio::test]
async fn plan_scopes_select_by_materialized_tier() {
    let db = seed_fixture().await;
    let scoped = |scope: PlanScope| {
        let mut req = request(PageSort::Test, true, 0, 100);
        req.scope = scope;
        req
    };
    let ids_of = |meta: &xray_tui_db::profiles_query::PageMeta| {
        let mut ids: Vec<i64> = meta.ids.iter().map(|id| EndpointId::get(*id)).collect();
        ids.sort_unstable();
        ids
    };

    // Successful = PROVEN (spec `2026-10-09-stab-bin-design` §5.3), not
    // "the representative bin is 0..=5": e1, e2, e4, e7 (real measurements),
    // and e5 — whose representative is its UNTESTED sibling (bin 12) but which
    // still holds the proven real link 107. That last row is the whole point of
    // the feature: a proven endpoint is not "New" because a sibling is
    // untested. e6 is a DNS-unresolved host and is excluded despite its stored
    // real measurement.
    let successful = db
        .profiles_page(&scoped(PlanScope::Successful))
        .await
        .expect("page");
    assert_eq!(ids_of(&successful), vec![1, 2, 4, 5, 7]);
    assert_eq!(successful.total, 5, "the count carries the scope too");

    // `New` is NOT proven AND untested: only e3 (a single untested link).
    let new = db
        .profiles_page(&scoped(PlanScope::SuccessfulAndNew))
        .await
        .expect("page");
    assert_eq!(ids_of(&new), vec![1, 2, 3, 4, 5, 7]);
    assert_eq!(new.total, 6);

    // ...and `New` alone is proven ∪ untested minus the proven ones.
    let untested = db
        .profiles_page(&scoped(PlanScope::New))
        .await
        .expect("page");
    assert_eq!(ids_of(&untested), vec![3]);
    assert_eq!(untested.total, 1);

    // Failed: NOT proven and carrying a failure marker. e6 is the DNS host
    // whose stored measurement sits in the name band — the row that shows
    // `[name]` and cannot otherwise be re-tested deliberately.
    let failed = db
        .profiles_page(&scoped(PlanScope::Failed))
        .await
        .expect("page");
    assert_eq!(ids_of(&failed), vec![6]);
    assert_eq!(failed.total, 1);

    // The default scope is the whole feed, and the walk pages the same set.
    let all = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page");
    assert_eq!(all.total, ALL_ENDPOINTS.len() as u64);
    let walked = db
        .profiles_walk_page(&scoped(PlanScope::Failed), true)
        .await
        .expect("walk");
    assert_eq!(walked.0, failed.ids, "the walk reads the same predicate");
    assert_eq!(walked.1, Some(1));
}

/// The walk page is the page query minus its per-page count: same ids in the
/// same order at every offset, and the total is returned only when the walk asks
/// for it — once, not once per page (the `O(feed²/200)` the batch plan loader
/// used to pay).
#[tokio::test]
async fn walk_pages_match_the_page_ids_and_count_once() {
    let db = seed_fixture().await;
    for sort in ALL_SORTS {
        for ascending in [true, false] {
            for limit in [1_usize, 3, 100] {
                let mut walked = Vec::new();
                let mut totals = Vec::new();
                let mut offset = 0;
                loop {
                    let (ids, total) = db
                        .profiles_walk_page(&request(sort, ascending, offset, limit), offset == 0)
                        .await
                        .expect("walk page");
                    totals.push(total);
                    if ids.is_empty() {
                        break;
                    }
                    walked.extend(ids.iter().map(|id| id.get()));
                    offset += limit;
                }
                let page = db
                    .profiles_page(&request(sort, ascending, 0, 100))
                    .await
                    .expect("page");
                assert_eq!(
                    walked,
                    page.ids.iter().map(|id| id.get()).collect::<Vec<_>>(),
                    "sort {sort:?} asc {ascending} limit {limit}"
                );
                assert_eq!(totals.first().copied().flatten(), Some(page.total));
                assert!(
                    totals[1..].iter().all(Option::is_none),
                    "only the first walk page pays the count"
                );
            }
        }
    }
}

#[tokio::test]
async fn count_narrows_with_search_and_group_filters() {
    let db = seed_fixture().await;
    let total = |req: PageRequest| {
        let db = &db;
        async move { db.profiles_page(&req).await.expect("count").total }
    };
    assert_eq!(total(request(PageSort::Test, true, 0, 10)).await, 8);

    let searched = total(PageRequest {
        search: Some("H1.".to_string()),
        ..request(PageSort::Test, true, 0, 10)
    })
    .await;
    assert_eq!(searched, 1, "search is case-insensitive on host");

    let port = total(PageRequest {
        search: Some("443".to_string()),
        ..request(PageSort::Test, true, 0, 10)
    })
    .await;
    assert_eq!(port, 8, "port match");

    let none = total(PageRequest {
        search: Some("%".to_string()),
        ..request(PageSort::Test, true, 0, 10)
    })
    .await;
    assert_eq!(none, 0, "LIKE metacharacters are escaped");
}

#[tokio::test]
async fn anchor_returns_each_rows_position_for_every_sort_and_direction() {
    let db = seed_fixture().await;
    for sort in ALL_SORTS {
        for ascending in [true, false] {
            let page = db
                .profiles_page(&request(sort, ascending, 0, 100))
                .await
                .expect("page");
            assert_eq!(page.ids.len(), 8, "{sort:?} {ascending}");
            for (position, id) in page.ids.iter().enumerate() {
                let anchored = db
                    .profiles_anchor(&request(sort, ascending, 0, 10), *id)
                    .await
                    .expect("anchor");
                assert_eq!(
                    anchored,
                    Some(position),
                    "anchor {sort:?} {ascending} {id:?}"
                );
            }
        }
    }
    let missing = db
        .profiles_anchor(&request(PageSort::Test, true, 0, 10), EndpointId::new(999))
        .await
        .expect("anchor missing");
    assert_eq!(missing, None);
}

#[tokio::test]
async fn descending_order_is_the_reverse_of_ascending_for_every_sort() {
    // The UI reverses the whole comparator (`cmp.reverse()`), so a descending
    // page must be the exact reverse of the ascending one, tiebreaks included.
    let db = seed_fixture().await;
    for sort in ALL_SORTS {
        let asc = db
            .profiles_page(&request(sort, true, 0, 100))
            .await
            .expect("asc");
        let desc = db
            .profiles_page(&request(sort, false, 0, 100))
            .await
            .expect("desc");
        let mut expected = asc.ids.clone();
        expected.reverse();
        assert_eq!(desc.ids, expected, "{sort:?}");
    }
}

#[tokio::test]
async fn link_writes_keep_the_stored_keys_current() {
    let db = Database::in_memory().await.expect("db");
    let mut conn = db.connection().await.expect("conn");
    seed_endpoint(&mut conn, 1, HostType::Dns, &["10.0.0.1"]).await;
    seed_endpoint(&mut conn, 2, HostType::Dns, &["10.0.0.2"]).await;
    drop(conn);

    let page = || async {
        db.profiles_page(&request(PageSort::Test, true, 0, 100))
            .await
            .expect("page")
            .ids
    };

    // `upsert_link` (the import / single-row path).
    db.upsert_link(&link_value(1, 101, None, None, 100))
        .await
        .expect("upsert a");
    db.upsert_link(&link_value(2, 102, None, None, 100))
        .await
        .expect("upsert b");
    assert_eq!(page().await, vec![EndpointId::new(1), EndpointId::new(2)]);

    // `apply_link_patches` (the batch-result path): a real result leads.
    db.apply_link_patches(&[LinkPatch {
        link: link_value(2, 102, Some(20), None, 100),
        groups: LinkGroups::RESULT,
    }])
    .await
    .expect("patch");
    assert_eq!(page().await, vec![EndpointId::new(2), EndpointId::new(1)]);

    // And the failure band follows the same route.
    db.apply_link_patches(&[LinkPatch {
        link: link_value(2, 102, None, Some("real"), 100),
        groups: LinkGroups::RESULT,
    }])
    .await
    .expect("patch");
    assert_eq!(page().await, vec![EndpointId::new(1), EndpointId::new(2)]);
}

/// The address set is part of the ordering law: a DNS host that resolves moves
/// out of the unresolved band, and the page must show it there immediately.
#[tokio::test]
async fn resolving_a_dns_host_moves_its_stored_key() {
    let db = seed_fixture().await;
    let unresolved = EndpointId::new(6); // dns host, no address, real 5 ms
    let before = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page")
        .ids;
    assert_eq!(before.last(), Some(&unresolved), "unresolved sinks");

    db.update_endpoint_resolution(
        unresolved,
        vec!["203.0.113.6".parse().expect("addr")],
        ts(200),
    )
    .await
    .expect("resolve");

    let after = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page")
        .ids;
    // It LEAVES the sunk position — that is the point of the test. The
    // ordering CLAIM is that e6 lands behind e7, not that e7 takes first place
    // (several endpoints tie on bin 0): e7's representative is `x_http`
    // (mimicry band 7 against e6's tcp row's 5), and inside a bin the stability
    // ties and the static weight decides, so e7's 9 ms leads e6's 5 ms. Under
    // the `x_http` label bug that order inverts and this assertion goes red.
    let e7 = after.iter().position(|id| *id == EndpointId::new(7));
    let e6 = after.iter().position(|id| *id == unresolved);
    assert!(
        e7 < e6,
        "e7's x_http representative outranks e6 on weight, not on its 9 ms: {after:?}"
    );
    let pos = after
        .iter()
        .position(|id| *id == unresolved)
        .expect("still present");
    assert!(
        pos < after.len() - 1,
        "the resolved endpoint LEFT the dns-err bin (no longer last): {after:?}"
    );
}

/// A TASK-only patch is key-neutral for an EXISTING link, but not when it
/// inserts a missing one: the insert writes the whole snapshot, so the
/// endpoint's key appears (or moves) and the page must show it.
#[tokio::test]
async fn a_result_patch_that_inserts_a_link_still_moves_the_key() {
    let db = Database::in_memory().await.expect("db");
    let mut conn = db.connection().await.expect("conn");
    seed_endpoint(&mut conn, 1, HostType::Dns, &["10.0.0.1"]).await;
    drop(conn);

    let page = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page")
        .ids;
    assert!(page.is_empty(), "no links, no key, not listed");

    // For a link that has never been persisted, the whole snapshot goes in
    // whatever groups the patch names — and the endpoint's keys follow.
    let link = link_value(1, 101, Some(25), None, 100);
    db.apply_link_patches(&[LinkPatch {
        link,
        groups: LinkGroups::RESULT,
    }])
    .await
    .expect("patch");

    let page = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page")
        .ids;
    assert_eq!(page, vec![EndpointId::new(1)], "the inserted link keys it");
}

/// Deleting an endpoint's links removes its key: the page drives from the rank
/// table, so a lingering key would list a linkless row.
#[tokio::test]
async fn purging_endpoints_drops_their_keys() {
    let db = seed_fixture().await;
    let purged = db.purge_expired(ts(100_000)).await.expect("purge");
    assert!(purged > 0, "the fixture's rows are older than the cutoff");
    let page = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page");
    assert!(page.ids.is_empty(), "got {:?}", page.ids);
    assert_eq!(page.total, 0);
}

#[tokio::test]
async fn anchor_and_page_agree_after_a_weight_change() {
    let db = seed_fixture().await;
    let before = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page");
    let moved = before.ids[0];

    // Move the leading endpoint to the bottom band (real error).
    toasty::sql::statement(
        "UPDATE profile_stats SET error = 1, error_kind = 'real', error_text = 'x' \
         WHERE endpoint_id = ?1",
    )
    .bind(moved.get())
    .exec(&mut db.connection().await.expect("conn"))
    .await
    .expect("mutate");
    // The raw statement bypassed the write paths, so refresh like they do.
    db.refresh_endpoint_ranks(&[moved]).await.expect("ranks");

    let after = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page");
    assert_ne!(after.ids[0], moved, "the row left the top");
    let anchored = db
        .profiles_anchor(&request(PageSort::Test, true, 0, 10), moved)
        .await
        .expect("anchor")
        .expect("present");
    assert_eq!(after.ids[anchored], moved, "anchor tracks the new position");
}

/// The tiers the panel renders, pinned per fixture endpoint. The order is the
/// Rust law's (there is no SQL expression left to disagree with it).
#[tokio::test]
async fn link_order_is_decision_16_order() {
    let db = seed_fixture().await;
    let ids: Vec<EndpointId> = ALL_ENDPOINTS
        .iter()
        .map(|id| EndpointId::new(*id))
        .collect();
    let rows = db.load_page_rows(&ids, true).await.expect("rows");
    assert_eq!(rows.len(), ids.len());
    assert!(rows.iter().all(|r| !r.links.is_empty()));

    let ids_of = |endpoint: i64| -> Vec<i64> {
        rows.iter()
            .find(|r| r.endpoint.id == EndpointId::new(endpoint))
            .expect("endpoint present")
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect()
    };
    // e1: the real success (30 ms) leads the fast error.
    assert_eq!(ids_of(1), vec![101, 102]);
    // e4: the minimum-weight link leads; the manual override is a display
    // choice and does not reorder the panel.
    assert_eq!(ids_of(4), vec![105, 106]);
    // e5: untested (tier 2) leads the measured-with-error link (tier 4).
    assert_eq!(ids_of(5), vec![108, 107]);
    // e6: unresolved DNS collapses the band; the only link leads.
    assert_eq!(ids_of(6), vec![109]);
    // e7: two real successes, then the name-resolution failure. The x_http link
    // (112) leads the slower 110 DESPITE its 9 ms against 7 ms: inside a tier the
    // static weight outranks latency (spec
    // `2026-10-01-static-config-weight-design`), and x_http scores a higher
    // mimicry band than tcp over the same security.
    assert_eq!(ids_of(7), vec![112, 110, 111]);
}

#[tokio::test]
async fn every_statement_runs_against_a_pushed_schema() {
    // Drift guard: a renamed or removed column must fail here, not in the TUI.
    let db = Database::in_memory().await.expect("in-memory db");
    let base = request(PageSort::Test, true, 0, 10);
    db.profiles_page(&base).await.expect("page");
    db.profiles_page(&base).await.expect("count");
    db.profiles_anchor(&base, EndpointId::new(1))
        .await
        .expect("anchor");
    db.load_page_projection(&[EndpointId::new(1)], true)
        .await
        .expect("projection");

    for sort in ALL_SORTS {
        for ascending in [true, false] {
            let req = PageRequest {
                sort,
                ascending,
                ..base.clone()
            };
            db.profiles_page(&req).await.expect("sorted page");
            db.profiles_page(&req).await.expect("sorted count");
        }
    }
    for view in [
        PurgatoryView::Active,
        PurgatoryView::Purgatory,
        PurgatoryView::All,
    ] {
        let req = PageRequest {
            view,
            ..base.clone()
        };
        db.profiles_page(&req).await.expect("view page");
    }
}

/// The page's rows come back in the page's order, with each row's links in the
/// decision-16 order the panel renders. That order comes from ONE place
/// ([`RankLink::key`]) — the SQL expression that used to re-derive it is gone,
/// because the two disagreed for a DNS-unresolved endpoint (its measured link
/// sorted above a failure; the law sinks every link of such an endpoint to
/// tier 5).
#[tokio::test]
async fn load_page_rows_preserves_page_and_link_order() {
    let db = seed_fixture().await;
    let req = request(PageSort::Test, true, 0, 2);
    let page = db.profiles_page(&req).await.expect("page");
    assert_eq!(page.ids.len(), 2);

    let rows = db.load_page_rows(&page.ids, true).await.expect("rows");
    let row_ids: Vec<i64> = rows.iter().map(|r| r.endpoint.id.get()).collect();
    let page_ids: Vec<i64> = page.ids.iter().map(|id| id.get()).collect();
    assert_eq!(row_ids, page_ids, "page order, not id order");

    for row in &rows {
        let unresolved = dns_unresolved(row);
        let weights = row.link_weights();
        let zero = xray_tui_db::weight::ZERO_WEIGHT;
        let keys: Vec<_> = row
            .links
            .iter()
            .map(|l| {
                let weight = weights.get(&l.protocol_id).copied().unwrap_or(zero);
                xray_tui_db::endpoint_rank::RankLink::new(l, weight).key(unresolved)
            })
            .collect();
        assert!(
            keys.windows(2).all(|w| w[0] <= w[1]),
            "endpoint {} links are not in decision-16 order: {keys:?}",
            row.endpoint.id.get()
        );
    }

    // Empty page: no query, no rows.
    assert!(
        db.load_page_rows(&[], true)
            .await
            .expect("empty")
            .is_empty()
    );
}

// ── Ordering parity: the SQL vs the Rust oracle ─────────────────────────
//
// The oracle is the production comparator (`EndpointRow::best_test_priority_key`
// and the display-link accessors), i.e. the decision-16 law and the
// display-preference rule as the rest of the codebase defines them. A mismatch
// means the SQL is wrong — the oracle is never adjusted to match it.

fn dns_unresolved(row: &xray_tui_db::models::EndpointRow) -> bool {
    row.endpoint.is_dns() && row.resolved_ips.is_empty()
}

/// The DISPLAY link as the spec defines it: the manual override when it names
/// an existing link, else the best measured link (real before fast, lowest
/// delay, then protocol id), else none.
///
/// Not `EndpointRow::active_link()`: that falls back to `links[selected_protocol]`
/// — the untested link when nothing is measured — while the ordering rule is
/// "no measured link, no value" (the SQL's `COALESCE(..., sentinel)`).
/// Ascending sort key per endpoint, mirroring `order_terms`.
///
/// A tuple, not a packed integer: the Test key is the FULL decision-16 tuple
/// `(tier, latency, -last_seen, protocol_id)` — dropping the recency term makes
/// the oracle disagree with the law on ties, which is how this test first
/// failed.
/// The lowest address key of a row, from its own values; the `x'ff'` sentinel
/// when it has none — the same value the SQL's `COALESCE` substitutes.
fn min_address_key(row: &xray_tui_db::models::EndpointRow) -> Vec<u8> {
    row.resolved_ips
        .iter()
        .map(|ip| xray_tui_db::endpoint_ip::key_of(*ip))
        .min()
        .unwrap_or_else(|| vec![0xff])
}

/// The ascending oracle key, one term per `order_terms` entry.
///
/// `Test` carries the weight as `u64::MAX - packed`: the law's key stores the
/// weight NEGATED so a single `.min()` implements "higher weight first", and
/// SQL reads the stored pack DESCENDING. Comparing the negated form here is
/// what pins that the two directions are the same order — a flip between them
/// fails THIS test, not the field.
/// The `Test` shape is `(band, bin, stab, neg_weight, domain, sub_domain,
/// addr, endpoint_id)` — the SQL term list, same arity and same ORDER. A
/// stab-less oracle compares equal whenever the fixture's stab values are
/// uniform, which is how a dropped or reordered `rank_stab` term stays green.
type OracleKey = (i64, i64, i64, u64, String, String, Vec<u8>, i64);

fn oracle_key(row: &xray_tui_db::models::EndpointRow, sort: PageSort) -> OracleKey {
    match sort {
        PageSort::Test => {
            // The binned law with stability: (bin, stab, neg_weight, domain,
            // sub_domain, addr, endpoint_id). bin/neg_weight come from the
            // representative link; the rest are endpoint-level.
            let (bin, stab, neg_weight, _seen, _pid) = row
                .best_test_priority_key(dns_unresolved(row))
                .unwrap_or((u8::MAX, u8::MAX, u64::MAX, i64::MAX, i64::MAX));
            let domain = row.endpoint.domain.clone();
            let sub_domain = row.endpoint.sub_domain.clone();
            let addr = if row.endpoint.is_dns() {
                Vec::new()
            } else {
                row.resolved_ips
                    .first()
                    .map(|ip| xray_tui_db::endpoint_ip::key_of(*ip))
                    .unwrap_or_default()
            };
            // band = "has a live link" (threshold ts(0)); NO_SEEN-only -> 1.
            let band = i64::from(row.links.iter().all(|l| l.purge_reason.is_some()));
            (
                band,
                i64::from(bin),
                i64::from(stab),
                neg_weight,
                domain,
                sub_domain,
                addr,
                row.endpoint.id.get(),
            )
        }
        PageSort::Ip => (
            0,
            0,
            0,
            0,
            String::new(),
            String::new(),
            Vec::new(),
            row.endpoint.id.get(),
        ),
        PageSort::Id => (
            0,
            0,
            row.endpoint.id.get(),
            0,
            String::new(),
            String::new(),
            Vec::new(),
            0,
        ),
        PageSort::Port => (
            0,
            0,
            i64::from(row.endpoint.port),
            0,
            String::new(),
            String::new(),
            Vec::new(),
            0,
        ),
    }
}

#[tokio::test]
async fn page_order_matches_the_rust_oracle_for_every_sort() {
    let db = seed_fixture().await;
    let all = db
        .profiles_page(&request(PageSort::Test, true, 0, 1000))
        .await
        .expect("all ids");
    let rows = db.load_page_rows(&all.ids, true).await.expect("rows");
    assert_eq!(rows.len(), 8, "fixture rows");

    for sort in ALL_SORTS {
        for ascending in [true, false] {
            // Every sort uses the oracle tuple; the `Ip` arm derives its key
            // from the row through the production codec.
            let mut expected: Vec<i64> = if sort == PageSort::Ip {
                // The address key, derived from the row's own values through
                // the production codec: `min` over the keys is what the SQL's
                // `min(ip_key)` reads, an endpoint with no address takes the
                // `x'ff'` sentinel (after every real key ascending), and the
                // DESC direction is the plain reversal.
                let mut v: Vec<(Vec<u8>, i64)> = rows
                    .iter()
                    .map(|r| (min_address_key(r), r.endpoint.id.get()))
                    .collect();
                v.sort_unstable();
                v.into_iter().map(|(_, id)| id).collect()
            } else {
                let mut v: Vec<(OracleKey, i64)> = rows
                    .iter()
                    .map(|r| (oracle_key(r, sort), r.endpoint.id.get()))
                    .collect();
                v.sort_unstable();
                v.into_iter().map(|(_, id)| id).collect()
            };
            if !ascending {
                expected.reverse();
            }

            let page = db
                .profiles_page(&request(sort, ascending, 0, 1000))
                .await
                .expect("page");
            let got: Vec<i64> = page.ids.iter().map(|id| id.get()).collect();
            assert_eq!(got, expected, "{sort:?} ascending={ascending}");
        }
    }
}

// ── The page projection (H1) ────────────────────────────────────────────

/// Seed rows that fill every projected column: `ports`/`last_source`/
/// `resolved_at` on the endpoint, both latency variants (one with an exit IP),
/// speed, traffic, both config types, a task slot, an error of each kind, a
/// dangling protocol reference, and protocols whose transport/security columns
/// differ. Raw statements, so the fixture reaches columns the typed writers
/// never set (`task_id`, `version`, a dangling `protocol_id`).
async fn seed_projection_fixture() -> Database {
    let db = Database::in_memory().await.expect("in-memory db");
    seed_projection_into(&db).await;
    db
}

/// Seed the projection fixture into an EXISTING database, so a file-backed one
/// exercises the raw reader path the in-memory tests fall back past.
async fn seed_projection_into(db: &Database) {
    let mut conn = db.connection().await.expect("conn");

    for stmt in [
        // e1: IPv4, multi-port spec, subscription source, override, two links.
        "INSERT INTO endpoints (id, domain, sub_domain, port, ports, last_source, \
         manual_protocol_override, resolved_at, created_at) VALUES \
         (1, 'a.example', '', 443, '[443,8443]', 'src-hash', 11, NULL, \
          1788220800)",
        // e2: DNS with a persisted resolution and a name failure.
        "INSERT INTO endpoints (id, domain, sub_domain, port, ports, last_source, \
         manual_protocol_override, resolved_at, created_at) VALUES \
         (2, 'b.example', '', 8443, '[]', NULL, NULL, 1788352245, 1788220801)",
        // e3: DNS with no resolution, a link whose protocol row is missing.
        "INSERT INTO endpoints (id, domain, sub_domain, port, ports, last_source, \
         manual_protocol_override, resolved_at, created_at) VALUES \
         (3, 'c.example', '', 443, '[]', NULL, NULL, NULL, \
          1788220802)",
        // e1's address: the Ip sort needs more than one endpoint to have a
        // key, and the fixture's only other DNS host (e3) must stay
        // unresolved for the tier-5 case above.
        "INSERT INTO endpoint_ip (endpoint_id, ip_key) VALUES \
         (1, x'04' || x'c0a80101')",
        // e2's addresses, written in the REVERSE of address order: the stored
        // key is what orders them, so a row order that disagrees with it still
        // reads back sorted (the property the whole `ip_key` design rests on).
        "INSERT INTO endpoint_ip (endpoint_id, ip_key) VALUES \
         (2, x'06' || x'20010db8000000000000000000000007')",
        "INSERT INTO endpoint_ip (endpoint_id, ip_key) VALUES \
         (2, x'04' || x'cb007108')",
        "INSERT INTO endpoint_ip (endpoint_id, ip_key) VALUES \
         (2, x'04' || x'cb007107')",
        // Protocols: ws+tls with every optional pinned, and tcp+reality bare.
        "INSERT INTO protocols (id, sig, proto_kind, transport_type, \
         security_type, security_sni, security_fp, security_insecure, config, \
         created_at) VALUES (11, 111, 'vless', 'ws', 'tls', 'sni.example', 'chrome', \
         1, 'null', 1788220803)",
        "INSERT INTO protocols (id, sig, proto_kind, transport_type, \
         security_type, security_sni, security_fp, security_insecure, config, \
         created_at) VALUES (13, 333, 'shadowsocks2022', 'tcp', 'reality', \
         'steal.example', NULL, NULL, 'null', 1788220804)",
        // A transport whose STORED label differs from its wire spelling:
        // toasty's embed writes the snake_case ident `x_http` where the wire
        // form (and every share URL) says `xhttp`. A reader that parses this
        // column with `TransportType::from_str` gets `Err` — which in the
        // ordering law is a silently persisted ZERO weight, and a stored page
        // order that disagrees with the in-memory panel. Found in review on a
        // real feed (145 `http_upgrade` + 169 `x_http` rows).
        "INSERT INTO protocols (id, sig, proto_kind, transport_type, \
         security_type, security_sni, security_fp, security_insecure, config, \
         created_at) VALUES (14, 444, 'vless', 'x_http', 'reality', \
         'steal.example', NULL, NULL, 'null', 1788220812)",
        // e1/link A: real ping with an exit IP, speed, traffic, a task slot.
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (11, 1, 1789034400, \
          1789038000, 'real', 42, '198.51.100.9', 1234567, \
          NULL, NULL, NULL, 11, 22, 33, 44, 1788220805, \
          1789038000, 3, 65535, 16)",
        // e1/link B: fast ping, a fast failure, form config.
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (13, 1, NULL, 1789041600, \
          'fast', 8, NULL, NULL, 1, 'fast', 'fast probe', 0, 0, 0, 0, \
          1788220806, 1789041600, 1, 0, 0)",
        // e1/link C: the x_http protocol row above, measured — so the raw-column
        // read that computes its weight is on the page path the parity golden
        // checks, not only on a synthetic parser test.
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (14, 1, NULL, 1789043400, \
          'real', 77, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, \
          1788220812, 1789043400, 1, 65535, 16)",
        // e2: name-resolution failure, no measurement.
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (11, 2, NULL, 1789045200, NULL, \
          NULL, NULL, NULL, 1, 'name', 'name probe', 0, 0, 0, 0, \
          1788220807, 1789045200, 2, 0, 0)",
        // e2's second link: the only PURGED one, so the purge filter's two
        // policies produce different pages from this fixture.
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, purge_reason, traffic_today_up, traffic_today_down, \
         traffic_total_up, traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (13, 2, NULL, 1789047000, NULL, \
          NULL, NULL, NULL, 1, 'real', 'reality error', 'reality_fallback', 0, 0, 0, 0, \
          1788220810, 1789047000, 1, 0, 0)",
        // e3: a measured success AND a real failure on one endpoint, plus a
        // link whose protocol row does not exist (LEFT JOIN -> no entry).
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (13, 3, NULL, 1789048800, \
          'real', 5, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, \
          1788220808, 1789048800, 1, 65535, 16)",
        "INSERT INTO profile_stats (protocol_id, endpoint_id, last_used_at, \
         last_seen_at, latency, latency_delay, latency_ip, speed_bps, error, \
         error_kind, error_text, traffic_today_up, traffic_today_down, traffic_total_up, \
         traffic_total_down, created_at, updated_at, version, stab_mask, stab_len) VALUES \
         (99, 3, NULL, 1789052400, NULL, \
          NULL, NULL, NULL, 1, 'real', 'real probe', 0, 0, 0, 0, \
          1788220809, 1789052400, 1, 0, 0)",
    ] {
        toasty::sql::statement(stmt)
            .exec(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("seed: {e}\n{stmt}"));
    }
    drop(conn);

    let ids: Vec<EndpointId> = (1..=3).map(EndpointId::new).collect();
    db.refresh_endpoint_ranks(&ids).await.expect("seed ranks");
}

fn assert_same_link(typed: &ProfileStats, projected: &ProfileStats, ctx: &str) {
    assert_eq!(
        typed.protocol_id, projected.protocol_id,
        "{ctx}: protocol_id"
    );
    assert_eq!(
        typed.endpoint_id, projected.endpoint_id,
        "{ctx}: endpoint_id"
    );
    assert_eq!(
        typed.last_used_at, projected.last_used_at,
        "{ctx}: last_used_at"
    );
    assert_eq!(
        typed.last_seen_at, projected.last_seen_at,
        "{ctx}: last_seen_at"
    );
    assert_eq!(typed.latency, projected.latency, "{ctx}: latency");
    assert_eq!(typed.speed_bps, projected.speed_bps, "{ctx}: speed_bps");
    assert_eq!(typed.error, projected.error, "{ctx}: error");
    // The stability ring is a projected column PAIR; asserting it here is what
    // makes the positional decode testable — a decoder reading them at the
    // wrong offset (or dropping them) otherwise passes this golden.
    assert_eq!(
        typed.stab_mask, projected.stab_mask,
        "{ctx}: stab_mask (projection slot order)"
    );
    assert_eq!(
        typed.stab_len, projected.stab_len,
        "{ctx}: stab_len (projection slot order)"
    );
    assert_eq!(typed.traffic, projected.traffic, "{ctx}: traffic");
    assert_eq!(typed.created_at, projected.created_at, "{ctx}: created_at");
    assert_eq!(typed.updated_at, projected.updated_at, "{ctx}: updated_at");
    assert_eq!(typed.version, projected.version, "{ctx}: version");
}

/// The raw reader (a file db → the direct turso connection, whose `query` uses
/// the UNCACHED `prepare`) must return exactly what the toasty path does. The
/// toasty driver caches every statement text in the connection forever, and the
/// projection inlines the page's ids, so its text is unique per page: the
/// file-backed path runs in production, and this pins it against the cached
/// path (the in-memory db, which has no second connection).
#[tokio::test]
async fn page_projection_raw_matches_toasty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_db = Database::open(dir.path().join("proj.db"))
        .await
        .expect("file db");
    assert!(
        file_db.uses_direct_reader(),
        "a file db has a direct reader"
    );
    seed_projection_into(&file_db).await;
    let mem_db = seed_projection_fixture().await;

    let ids: Vec<EndpointId> = (1..=3).map(EndpointId::new).collect();
    for include_purged in [true, false] {
        let raw = file_db
            .load_page_projection(&ids, include_purged)
            .await
            .expect("raw rows");
        let cached = mem_db
            .load_page_projection(&ids, include_purged)
            .await
            .expect("cached rows");
        let ctx = format!("include_purged = {include_purged}");
        assert_eq!(raw.len(), cached.len(), "{ctx}: row count");
        for (raw, cached) in raw.iter().zip(&cached) {
            assert_eq!(raw.endpoint.id, cached.endpoint.id, "{ctx}: endpoint id");
            assert_eq!(raw.resolved_ips, cached.resolved_ips, "{ctx}: resolved_ips");
            assert_eq!(
                raw.protocols.len(),
                cached.protocols.len(),
                "{ctx}: protocol count"
            );
            assert_eq!(raw.links.len(), cached.links.len(), "{ctx}: link count");
            for (raw, cached) in raw.links.iter().zip(&cached.links) {
                assert_eq!(
                    raw.protocol_id, cached.protocol_id,
                    "{ctx}: link protocol_id"
                );
                assert_eq!(raw.latency, cached.latency, "{ctx}: link latency");
                assert_eq!(raw.error, cached.error, "{ctx}: link error");
                assert_eq!(raw.traffic, cached.traffic, "{ctx}: link traffic");
            }
        }
    }
}

/// The projection is the typed hydration's equal: same endpoints, same links
/// in the same order, same protocol columns — and the only difference is that
/// the three deferred JSON carriers come back unloaded.
#[tokio::test]
async fn page_projection_matches_the_orm_rows() {
    let db = seed_projection_fixture().await;
    let ids: Vec<EndpointId> = (1..=3).map(EndpointId::new).collect();

    // Both purge policies: the projection applies the Active view's filter in
    // SQL, the typed path in Rust, and the two must keep agreeing. The fixture
    // carries one purged link, so the policies must actually differ.
    let mut link_counts = Vec::new();
    for include_purged in [true, false] {
        let typed = db
            .load_page_rows(&ids, include_purged)
            .await
            .expect("typed rows");
        let projected = db
            .load_page_projection(&ids, include_purged)
            .await
            .expect("projected rows");
        assert_eq!(
            typed.len(),
            projected.len(),
            "one row per id (include_purged = {include_purged})"
        );
        for (typed, projected) in typed.iter().zip(&projected) {
            assert_eq!(
                typed.links.len(),
                projected.links.len(),
                "the same links survive the filter (include_purged = {include_purged})"
            );
        }
        link_counts.push(typed.iter().map(|r| r.links.len()).sum::<usize>());
    }
    assert_eq!(
        link_counts,
        vec![7, 6],
        "the purged link is loaded only when the view asks for it (the x_http \
         protocol's link is in both counts)"
    );

    let typed = db.load_page_rows(&ids, true).await.expect("typed rows");
    let projected = db
        .load_page_projection(&ids, true)
        .await
        .expect("projected rows");

    assert_eq!(typed.len(), projected.len(), "one row per id");
    for (typed, projected) in typed.iter().zip(&projected) {
        let ctx = format!("endpoint {}", typed.endpoint.id.get());
        assert_eq!(typed.endpoint.id, projected.endpoint.id, "{ctx}: id");
        assert_eq!(
            typed.endpoint.domain, projected.endpoint.domain,
            "{ctx}: domain"
        );
        assert_eq!(
            typed.endpoint.sub_domain, projected.endpoint.sub_domain,
            "{ctx}: sub_domain"
        );
        assert_eq!(typed.endpoint.port, projected.endpoint.port, "{ctx}: port");
        assert_eq!(
            typed.endpoint.ports, projected.endpoint.ports,
            "{ctx}: ports"
        );
        assert_eq!(
            typed.endpoint.last_source, projected.endpoint.last_source,
            "{ctx}: last_source"
        );
        assert_eq!(
            typed.endpoint.manual_protocol_override, projected.endpoint.manual_protocol_override,
            "{ctx}: manual_protocol_override"
        );
        assert_eq!(
            typed.resolved_ips, projected.resolved_ips,
            "{ctx}: resolved_ips"
        );
        assert_eq!(
            typed.endpoint.resolved_at, projected.endpoint.resolved_at,
            "{ctx}: resolved_at"
        );
        assert_eq!(
            typed.endpoint.created_at, projected.endpoint.created_at,
            "{ctx}: created_at"
        );

        assert_eq!(
            typed.links.len(),
            projected.links.len(),
            "{ctx}: link count"
        );
        for i in 0..typed.links.len() {
            assert_same_link(
                &typed.links[i],
                &projected.links[i],
                &format!("{ctx}: link {i}"),
            );
        }
        assert_eq!(
            typed.selected_protocol, projected.selected_protocol,
            "{ctx}: selected_protocol"
        );
        assert_eq!(typed.expanded, projected.expanded, "{ctx}: expanded");

        assert_eq!(
            typed.protocols.len(),
            projected.protocols.len(),
            "{ctx}: protocol count"
        );
        for (id, typed_protocol) in &typed.protocols {
            let projected_protocol = projected
                .protocols
                .get(id)
                .unwrap_or_else(|| panic!("{ctx}: protocol {id:?} missing from the projection"));
            assert_eq!(
                typed_protocol.id, projected_protocol.id,
                "{ctx}: protocol id"
            );
            assert_eq!(
                typed_protocol.sig, projected_protocol.sig,
                "{ctx}: protocol sig"
            );
            assert_eq!(
                typed_protocol.proto_kind, projected_protocol.proto_kind,
                "{ctx}: proto_kind"
            );
            assert_eq!(
                typed_protocol.transport.r#type, projected_protocol.transport.r#type,
                "{ctx}: transport type"
            );
            assert_eq!(
                typed_protocol.security.r#type, projected_protocol.security.r#type,
                "{ctx}: security type"
            );
            assert_eq!(
                typed_protocol.security.sni, projected_protocol.security.sni,
                "{ctx}: security sni"
            );
            assert_eq!(
                typed_protocol.security.fp, projected_protocol.security.fp,
                "{ctx}: security fp"
            );
            assert_eq!(
                typed_protocol.security.insecure, projected_protocol.security.insecure,
                "{ctx}: security insecure"
            );
            assert_eq!(
                typed_protocol.created_at, projected_protocol.created_at,
                "{ctx}: protocol created_at"
            );
            // The page never reads a protocol's JSON: the projection leaves it
            // unloaded, so a consumer that needs it must re-read the row.
            assert!(
                projected_protocol.config.is_unloaded(),
                "{ctx}: the projection must not load `protocols.config`"
            );
        }
    }

    // The DNS-unresolved collapse (decision 16, tier 5) reached the page rows:
    // every link of such an endpoint sinks, so the newest one leads even though
    // its sibling carries a live measurement — the retired SQL link order put
    // the measured link first here.
    //
    // INSIDE the tier the weight decides (spec
    // `2026-10-01-static-config-weight-design`), so recency is only the
    // tiebreak and the verdict FLIPS relative to the pre-weight law: protocol
    // 13 is tcp+reality (security band 10) while 99 has no protocol row at all
    // (the LEFT JOIN misses), which is the zero weight — "worst". The measured
    // link leads on weight, not on being newer.
    let dns_row = projected
        .iter()
        .find(|r| r.endpoint.id.get() == 3)
        .expect("endpoint 3");
    assert!(xray_tui_db::endpoint_rank::dns_unresolved(dns_row));
    assert_eq!(
        dns_row
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect::<Vec<_>>(),
        vec![13, 99],
        "inside tier 5 the static weight leads, ahead of recency"
    );
    assert!(
        dns_row.links[0].latency.is_some(),
        "the leading link is the measured one, chosen by weight rather than by recency"
    );
}

/// The page ids are the only input: an empty page costs no statement, and the
/// returned rows keep the caller's order rather than the id order.
#[tokio::test]
async fn page_projection_keeps_the_requested_order_and_skips_empty_pages() {
    let db = seed_projection_fixture().await;
    assert!(
        db.load_page_projection(&[], true)
            .await
            .expect("empty page")
            .is_empty()
    );

    let shuffled = vec![EndpointId::new(3), EndpointId::new(1), EndpointId::new(2)];
    let rows = db
        .load_page_projection(&shuffled, true)
        .await
        .expect("projected rows");
    let got: Vec<i64> = rows.iter().map(|r| r.endpoint.id.get()).collect();
    assert_eq!(got, vec![3, 1, 2]);
}

/// A patch writes ONLY its own column groups: the columns another writer owns
/// (`last_used_at`, `last_seen_at`, `created_at`) keep their persisted values.
/// This is why the flush writes per-group UPDATEs instead of replacing the
/// whole row — `update_last_used` runs on every connect, and a batch's staged
/// snapshot is older than that write.
#[tokio::test]
async fn link_patches_leave_columns_outside_their_groups_alone() {
    let db = seed_projection_fixture().await;
    let link = db
        .read_link_row(ProtocolId::new(11), EndpointId::new(1))
        .await
        .expect("read")
        .expect("link");
    let untouched_used = link.last_used_at;
    let untouched_seen = link.last_seen_at;
    let untouched_created = link.created_at;
    assert!(untouched_used.is_some(), "the fixture pins a connect time");

    // A RESULT-only patch that clears the measurement, with a stale snapshot
    // for the columns it does not own.
    let mut stale = link.clone();
    stale.last_seen_at = ts(0);
    stale.created_at = ts(0);
    stale.last_used_at = None;
    stale.speed_bps = None;
    stale.latency = None;
    assert_eq!(
        db.apply_link_patches(&[xray_tui_db::LinkPatch {
            link: stale,
            groups: LinkGroups::RESULT,
        }])
        .await
        .expect("patch"),
        1
    );

    let after = db
        .read_link_row(ProtocolId::new(11), EndpointId::new(1))
        .await
        .expect("read")
        .expect("link");
    assert_eq!(after.latency, None, "the RESULT group landed");
    assert_eq!(after.error, None, "the RESULT group landed");
    assert_eq!(
        after.last_seen_at, untouched_seen,
        "last_seen_at is not the patch's to write"
    );
    assert_eq!(
        after.created_at, untouched_created,
        "created_at is not the patch's to write"
    );
    assert_eq!(
        after.last_used_at, untouched_used,
        "a connect time is not the patch's to write"
    );
}

/// A patch for a link that has never been persisted inserts the whole
/// snapshot, and the endpoint's ordering key reflects it immediately.
#[tokio::test]
async fn link_patch_inserts_a_missing_row_and_refreshes_its_key() {
    let db = seed_projection_fixture().await;
    let mut fresh = db
        .read_link_row(ProtocolId::new(11), EndpointId::new(1))
        .await
        .expect("read")
        .expect("link");
    fresh.protocol_id = ProtocolId::new(4242);
    fresh.latency = Some(xray_tui_db::models::Latency::Real { delay: 5, ip: None });
    fresh.error = None;

    assert_eq!(
        db.apply_link_patches(&[xray_tui_db::LinkPatch {
            link: fresh,
            groups: LinkGroups::RESULT,
        }])
        .await
        .expect("patch"),
        1
    );

    let inserted = db
        .read_link_row(ProtocolId::new(4242), EndpointId::new(1))
        .await
        .expect("read")
        .expect("inserted");
    assert_eq!(
        inserted.latency,
        Some(xray_tui_db::models::Latency::Real { delay: 5, ip: None })
    );
}

/// The weight column is materialized, NOT NULL, and read back as the packed
/// bytes the law compares — an endpoint with no protocol row carries the zero
/// ("worst") pack rather than a NULL, because a NULL here is not a mis-sort but
/// a `profiles_anchor` error (it binds every term's value back).
#[tokio::test]
async fn every_rank_row_carries_a_non_null_weight() {
    let db = seed_projection_fixture().await;
    let mut conn = db.connection().await.expect("conn");
    let rows = toasty::sql::query(
        "SELECT endpoint_id, rank_weight, typeof(rank_weight) FROM endpoint_rank \
         ORDER BY endpoint_id",
    )
    .exec(&mut conn)
    .await
    .expect("read rank rows");
    assert!(!rows.is_empty(), "the fixture produced rank rows");
    for row in &rows {
        let toasty::stmt::Value::Record(record) = row else {
            panic!("expected a record");
        };
        let weight = &record.fields[1];
        assert!(
            !matches!(weight, toasty::stmt::Value::Null),
            "endpoint {:?} has a NULL weight, which breaks profiles_anchor",
            record.fields[0]
        );
        assert_eq!(
            record.fields[2],
            toasty::stmt::Value::String("blob".into()),
            "the weight must be a BLOB: an INTEGER sorts a value >= 2^63 last"
        );
    }
}

/// The page's Test order is served by an index that actually carries the weight
/// term. `CREATE INDEX IF NOT EXISTS` makes an edited column list a no-op on an
/// existing database, so this asserts the INDEX'S OWN definition — the thing a
/// fresh-database page test can never see.
#[tokio::test]
async fn the_test_order_has_an_index_that_includes_the_weight() {
    let db = seed_projection_fixture().await;
    let mut conn = db.connection().await.expect("conn");
    let rows = toasty::sql::query(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'endpoint_rank'",
    )
    .exec(&mut conn)
    .await
    .expect("read indexes");
    let ddl: Vec<String> = rows
        .iter()
        .filter_map(|row| match row {
            toasty::stmt::Value::Record(record) => match (&record.fields[0], &record.fields[1]) {
                (toasty::stmt::Value::String(name), toasty::stmt::Value::String(sql)) => {
                    Some(format!("{name}: {sql}"))
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    let weight_index = ddl
        .iter()
        .find(|sql| sql.starts_with("endpoint_rank_key_v2:"))
        .expect("the covering index exists");
    assert!(
        weight_index.contains("rank_weight DESC"),
        "the weight term must be indexed DESCENDING to serve the ORDER BY: {weight_index}"
    );
    assert!(
        weight_index.contains("rank_bin") && weight_index.contains("rank_domain"),
        "the index must still lead with the terms before the weight: {weight_index}"
    );
    assert!(
        weight_index.contains("rank_stab"),
        "the stability term must be indexed between bin and weight: {weight_index}"
    );
    assert!(
        weight_index.trim_end_matches(')').ends_with("rank_proven"),
        "rank_proven must ride LAST as a covering column: {weight_index}"
    );
}

/// The compiled weight tables are code, so the DB stamps their version. A
/// mismatch must recompute every key — the ONLY trigger that can replace the
/// all-zero default `ADD COLUMN` materialized for pre-existing rows.
#[tokio::test]
async fn a_stale_weight_version_is_recomputed_at_open() {
    let dir = std::env::temp_dir().join(format!("xray-tui-weight-version-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("data.db");
    let _ = std::fs::remove_file(&path);

    {
        let db = Database::open(&path).await.expect("open");
        // Real data: without a link, "no endpoint stayed at the zero pack" would
        // hold trivially on an empty database and prove nothing.
        let endpoint = Endpoint {
            id: EndpointId::new(1),
            domain: Endpoint::derive_domain("w.example", HostType::Ipv4).0,
            sub_domain: Endpoint::derive_domain("w.example", HostType::Ipv4).1,
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: ts(1),
            links: Deferred::default(),
            group_links: Deferred::default(),
        };
        db.upsert_endpoint(&endpoint).await.expect("endpoint");
        let protocol = Protocol {
            id: ProtocolId::new(11),
            sig: 11,
            proto_kind: ProtocolKind::Vless,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::Reality,
                sni: Some("steal.example".to_string()),
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Vless(VlessConfig {
                uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport: TransportConfig::Tcp,
                encryption: None,
                flow: None,
                path: None,
                splice: None,
                remarks: None,
                mux: None,
            }))),
            created_at: ts(1),
            links: Deferred::default(),
        };
        db.upsert_protocol(&protocol).await.expect("protocol");
        db.upsert_link(&link_value(1, 11, Some(20), None, ts(2)))
            .await
            .expect("link");

        // Pretend this database was written by an older build: wrong stamp, and
        // every stored weight wiped back to the all-zero default.
        let mut conn = db.connection().await.expect("conn");
        toasty::sql::query(
            "UPDATE rank_weight_meta SET weight_version = weight_version - 1 WHERE id = 0",
        )
        .exec(&mut conn)
        .await
        .expect("downgrade the stamp");
        toasty::sql::query("UPDATE endpoint_rank SET rank_weight = x'0000000000000000'")
            .exec(&mut conn)
            .await
            .expect("wipe the weights");
        drop(conn);
        drop(db);
    }

    {
        let db = Database::open(&path).await.expect("reopen");
        let mut conn = db.connection().await.expect("conn");
        let stamped =
            toasty::sql::query("SELECT weight_version FROM rank_weight_meta WHERE id = 0")
                .exec(&mut conn)
                .await
                .expect("read stamp");
        assert_eq!(
            stamped[0],
            toasty::stmt::Value::Record(toasty_core::stmt::ValueRecord::from_vec(vec![
                toasty::stmt::Value::I64(xray_tui_db::endpoint_rank::key_inputs_version()),
            ])),
            "the open rewrites the stamp to the running code's version"
        );
        let zeros = toasty::sql::query(
            "SELECT COUNT(*) FROM endpoint_rank WHERE rank_weight = x'0000000000000000'",
        )
        .exec(&mut conn)
        .await
        .expect("count zero weights");
        assert_eq!(
            zeros[0],
            toasty::stmt::Value::Record(toasty_core::stmt::ValueRecord::from_vec(vec![
                toasty::stmt::Value::I64(0),
            ])),
            "a stale stamp must rebuild the weights; every endpoint staying at the \
             zero pack means the whole feature silently does nothing"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `profiles_anchor` binds every ordering term's value back into a comparison,
/// and this engine refuses to type a NULL there — so `rank_weight` must be
/// `NOT NULL`. This proves the DEFAULT is a legal anchor term: a row that has
/// only ever had the column added to it still re-anchors instead of erroring.
/// (The `NOT NULL` in the DDL is what makes this true; the test is what notices
/// if that ever changes.)
#[tokio::test]
async fn anchoring_works_on_a_row_carrying_only_the_weight_default() {
    let db = seed_projection_fixture().await;
    let mut conn = db.connection().await.expect("conn");
    toasty::sql::query("UPDATE endpoint_rank SET rank_weight = x'0000000000000000'")
        .exec(&mut conn)
        .await
        .expect("reset to the default pack");

    let page = db
        .profiles_page(&request(PageSort::Test, true, 0, 100))
        .await
        .expect("page over default-weighted rows");
    assert!(!page.ids.is_empty(), "the fixture still has rows");

    for ascending in [true, false] {
        for offset in [0usize, 1, 3] {
            for id in page.ids.iter().take(3) {
                db.profiles_anchor(&request(PageSort::Test, ascending, offset, 100), *id)
                    .await
                    .unwrap_or_else(|e| panic!("anchor must not error on the default pack: {e}"));
            }
        }
    }
}
