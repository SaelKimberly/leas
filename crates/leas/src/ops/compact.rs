//! Special maintenance commands.
//!
//! - [`spawn_compact`]: merge endpoints that are PROVABLY the same server.
//!   The pair criterion (see `leas_db::merge` for the law): same port, a
//!   shared `protocol_id`, AND an `endpoint_ip` overlap. `protocol_id` is
//!   host-independent, so it only NARROWS — the address overlap is what
//!   identifies the server. Applies directly (the user's explicit choice);
//!   the actions-log report is the only audit trail.
//! - [`spawn_dns_retry`]: mass re-resolution of every DNS endpoint whose
//!   address set is empty, force-bypassing the TTL. Purgatory included.
//!
//! Both run OFF the UI task — a whole-table scan plus the merges would freeze
//! input/render inline (the reason `ProfilesRowsReady` and `RetentionPurged`
//! exist) — and report through `CoreEvent::CompactFinished` /
//! `CoreEvent::DnsRetryTargets`. Progress renders on the same surfaces the
//! batch pipeline drives (status bar + Actions-Log bars) via the shared
//! `MaintMeters` in `AppState::maint_progress`: `scan` while the table walk
//! runs, then `name` (DNS lookups) and `comp` (merges).

use crate::state::AppState;
use leas_db::models::{EndpointId, EndpointRow, PurgatoryView};
use leas_db::profiles_query::PageSort;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

/// How many rows one scan page loads. The scan walks the WHOLE table, so a
/// reference-size feed (74k) takes ~15 pages.
const SCAN_PAGE_SIZE: usize = 5_000;

/// Merge passes over the table: one pass collapses whole connected
/// components, so a chain of aliases (A≈B, B≈C) converges in one run; the
/// bound only caps pathological growth.
const MAX_PASSES: usize = 5;

/// Walk the whole table once, collecting rows with their addresses. The scan
/// meter's `total` is known after the first page (the filtered total); `done`
/// counts rows read.
async fn load_all_rows(
    db: &Arc<leas_db::Database>,
    purgatory_ttl_secs: i64,
    error_ttl_hours: Option<i64>,
    scan: Option<&crate::types::PhaseMeters>,
) -> Result<Vec<EndpointRow>, leas_db::DatabaseError> {
    let mut load = crate::ops::profiles::ProfilesLoad {
        // The command walks the WHOLE table regardless of the tab's view or
        // the user's search — unfiltered by definition.
        view: PurgatoryView::All,
        purgatory_ttl_secs,
        error_ttl_hours,
        search: None,
        sort: PageSort::Test,
        ascending: true,
        offset: 0,
        limit: SCAN_PAGE_SIZE,
        group_id: None,
    };

    let mut rows = Vec::new();
    loop {
        load.offset = rows.len();
        let (page, meta) = crate::ops::profiles::load_profiles_rows(db, &load).await?;
        let count = page.len();
        if count == 0 {
            break;
        }
        if let Some(scan) = scan {
            scan.total.store(meta.total as u32, Ordering::Relaxed);
            scan.done
                .store(rows.len() as u32 + count as u32, Ordering::Relaxed);
        }
        let done = load.offset + count >= meta.total as usize;
        rows.extend(page);
        if done {
            break;
        }
    }
    Ok(rows)
}

/// The active protocol's SNI for a row, for the resolve dispatch.
fn row_sni(row: &EndpointRow) -> Option<String> {
    let host = row.endpoint.dns_name();
    row.active_protocol()
        .and_then(|(_, p)| crate::ops::enrich::extract_sni(p, &host))
}

/// One merge the planner decided on: everything in `absorbed` collapses into
/// `survivor`.
struct Component {
    survivor: EndpointId,
    absorbed: Vec<EndpointId>,
}

/// What one planning pass decided, plus the live rows it refused to touch.
struct Plan {
    components: Vec<Component>,
    /// Endpoints sharing a component with the CONNECTED endpoint: skipped,
    /// reported instead of merged.
    skipped_live: Vec<EndpointId>,
}

/// Group endpoints by `(protocol_id, port)` — the narrowing half of the pair
/// criterion — and union every overlapping-address pair into a connected
/// component, so a chain of aliases (A≈B, B≈C) collapses in one run instead
/// of leaving C behind after B was absorbed.
fn plan_components(rows: &[EndpointRow], live_endpoint: Option<i64>) -> Plan {
    // Union-find over row indexes; edges are address overlaps.
    const fn find(parent: &[usize], mut x: usize) -> usize {
        while parent[x] != x {
            x = parent[x];
        }
        x
    }
    let mut groups: HashMap<(i64, u16), Vec<usize>> = HashMap::new();
    for (idx, row) in rows.iter().enumerate() {
        if row.resolved_ips.is_empty() {
            continue;
        }
        for pid in row.links.iter().map(|l| l.protocol_id.get()) {
            groups
                .entry((pid, row.endpoint.port))
                .or_default()
                .push(idx);
        }
    }

    let mut parent: Vec<usize> = (0..rows.len()).collect();
    for members in groups.values() {
        for (a_pos, &i) in members.iter().enumerate() {
            for &j in &members[a_pos + 1..] {
                let (row_i, row_j) = (&rows[i], &rows[j]);
                if row_i
                    .resolved_ips
                    .iter()
                    .any(|ip| row_j.resolved_ips.contains(ip))
                {
                    let (ra, rb) = (find(&parent, i), find(&parent, j));
                    if ra != rb {
                        parent[rb.max(ra)] = ra.min(rb);
                    }
                }
            }
        }
    }

    // Assemble components: per root, pick the survivor and collect absorbed.
    let mut by_root: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, row) in rows.iter().enumerate() {
        if row.resolved_ips.is_empty() {
            continue;
        }
        by_root.entry(find(&parent, idx)).or_default().push(idx);
    }

    let mut plan = Plan {
        components: Vec::new(),
        skipped_live: Vec::new(),
    };
    for members in by_root.values() {
        if members.len() < 2 {
            continue;
        }
        // Survivor: DNS host over IP-literal, else the lower endpoint id —
        // `pick_survivor` folded over the members.
        let mut survivor = members[0];
        for &m in &members[1..] {
            let picked = leas_db::merge::pick_survivor(
                rows[survivor].endpoint.id,
                rows[survivor].endpoint.is_dns(),
                rows[m].endpoint.id,
                rows[m].endpoint.is_dns(),
            );
            if picked == leas_db::merge::Survivor::Right {
                survivor = m;
            }
        }
        let mut absorbed = Vec::new();
        for m in members.iter().copied().filter(|&m| m != survivor) {
            let id = rows[m].endpoint.id;
            // The endpoint the user is CONNECTED through must never be
            // absorbed: its row is live traffic.
            if Some(id.get()) == live_endpoint {
                plan.skipped_live.push(id);
            } else {
                absorbed.push(id);
            }
        }
        if !absorbed.is_empty() {
            plan.components.push(Component {
                survivor: rows[survivor].endpoint.id,
                absorbed,
            });
        }
    }
    plan
}

/// Flush the write-behind drivers, then drain everything staged for the
/// absorbed ids.
///
/// No FKs (ADR 0011): a patch flushing after the delete would silently
/// RE-CREATE an orphan `profile_stats` / `endpoint_ip` row, not error. The
/// drain is the anti-resurrection guard, and it covers BOTH specs — `LinkSpec`
/// is keyed `(protocol_id, endpoint_id, group)`, `CountrySpec` by endpoint id.
async fn flush_and_drain(
    link_stage: &Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    absorbed_ids: &[i64],
) -> Result<(), leas_db::DatabaseError> {
    link_stage.flush().await?;
    link_stage.discard_where(|k| absorbed_ids.contains(&k.1.get()));
    crate::ops::enrich::discard_country_for(absorbed_ids);
    Ok(())
}

/// Install the maintenance meters and the rate sampler for the run.
fn install_meters(state: &mut AppState) -> Arc<crate::types::MaintMeters> {
    let meters = Arc::new(crate::types::MaintMeters {
        scan: Arc::default(),
        name: Arc::default(),
        comp: Arc::default(),
    });
    state.maint_progress = Some(Arc::clone(&meters));
    spawn_rate_sampler(Arc::clone(&meters));
    meters
}

/// Sample results/s for the ETA display, at most once per second — the same
/// sampling the batch pipeline does for its meters. Stops once the run's
/// active phase completed (or an hour passed).
fn spawn_rate_sampler(meters: Arc<crate::types::MaintMeters>) {
    tokio::spawn(async move {
        let mut prev_name = 0u32;
        let mut prev_comp = 0u32;
        for _ in 0..3600 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let phases = [
                (&meters.name, &mut prev_name),
                (&meters.comp, &mut prev_comp),
            ];
            for (phase, prev) in phases {
                let done = phase.done.load(Ordering::Relaxed);
                let total = phase.total.load(Ordering::Relaxed);
                let was = std::mem::replace(prev, done);
                if total > 0 && done < total {
                    phase
                        .rate_milli
                        .store(done.saturating_sub(was) * 1000, Ordering::Relaxed);
                }
            }
            let complete = |p: &crate::types::PhaseMeters| {
                p.total.load(Ordering::Relaxed) > 0
                    && p.done.load(Ordering::Relaxed) >= p.total.load(Ordering::Relaxed)
            };
            if complete(&meters.name) || complete(&meters.comp) {
                return;
            }
        }
    });
}

/// Merge every provably-duplicate endpoint into its component's survivor.
/// Runs OFF the event loop; reports through `CoreEvent::CompactFinished`.
pub fn spawn_compact(state: &mut AppState) {
    if state.maint_progress.is_some() {
        state.log_trace(
            "info",
            "tui::ops::compact",
            "Maintenance already running — start it again when the bars come down",
        );
        return;
    }
    let db = Arc::clone(&state.db);
    let live_endpoint = state.connected_protocol_id;
    let purgatory_ttl_secs = state.purgatory_ttl_secs;
    let error_ttl_hours = state.config.speed_test.error_ttl_hours;
    let link_stage = Arc::clone(&state.link_stage);
    let tx = state.core_event_tx.clone();
    let meters = install_meters(state);
    let comp = meters.comp.clone();
    let scan = meters.scan.clone();
    tokio::spawn(async move {
        let send = |merged: usize, text: String| {
            if let Some(tx) = &tx {
                let _ = tx.try_send(crate::types::CoreEvent::CompactFinished { merged, text });
            }
        };

        let mut total_merged = 0usize;
        let mut report = String::new();
        let mut skipped_live: Vec<EndpointId> = Vec::new();
        let mut pass_merges;
        for _ in 0..MAX_PASSES {
            let rows = match load_all_rows(
                &db,
                purgatory_ttl_secs,
                error_ttl_hours,
                Some(scan.as_ref()),
            )
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    send(0, format!("Compact scan failed: {e}"));
                    return;
                }
            };
            let plan = plan_components(&rows, live_endpoint);
            if plan.components.is_empty() {
                break;
            }

            let absorbed_ids: Vec<i64> = plan
                .components
                .iter()
                .flat_map(|c| c.absorbed.iter().map(|id| id.get()))
                .collect();
            // The Comp bar's denominator: everything THIS pass plans to merge
            // (a failed merge is still consumed work — it counts done).
            comp.total
                .fetch_add(absorbed_ids.len() as u32, Ordering::Relaxed);

            if let Err(e) = flush_and_drain(&link_stage, &absorbed_ids).await {
                send(0, format!("Compact: staging flush failed: {e}"));
                return;
            }

            pass_merges = 0;
            for c in &plan.components {
                for absorbed in &c.absorbed {
                    match db.merge_endpoints(c.survivor, *absorbed).await {
                        Ok(r) => {
                            pass_merges += 1;
                            let _ = writeln!(
                                report,
                                "  {} absorbed into {}: {} link(s) moved, {} collision(s) ({} taken from the absorbed side), {} address(es) added",
                                r.absorbed.get(),
                                r.survivor.get(),
                                r.links_moved,
                                r.links_collided,
                                r.collisions_won_by_absorbed,
                                r.addresses_moved,
                            );
                        }
                        Err(e) => {
                            let _ = writeln!(
                                report,
                                "  merge {} → {} FAILED: {e}",
                                absorbed.get(),
                                c.survivor.get()
                            );
                        }
                    }
                    comp.done.fetch_add(1, Ordering::Relaxed);
                }
            }
            // The live row only ever lands in `skipped_live` — record the
            // refusals from every pass.
            skipped_live.extend(plan.skipped_live);
            total_merged += pass_merges;
            if pass_merges == 0 {
                break;
            }
        }

        let mut text = if total_merged == 0 {
            "Compact: no duplicate endpoints found".to_owned()
        } else {
            format!("Compact: {total_merged} endpoint(s) merged\n{report}")
        };
        if !skipped_live.is_empty() {
            let _ = write!(
                text,
                "\n  skipped (connected): {}",
                skipped_live
                    .iter()
                    .map(|id| id.get().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        send(total_merged, text.trim_end().to_owned());
    });
}

/// Re-run the DNS lookup for every endpoint with an empty address set.
///
/// Never-attempted and previously-failed names alike, TTL bypassed, still
/// bounded by `RESOLVE_SEM` (the `Maintenance` trigger). The scan runs OFF
/// the event loop; the handler dispatches the lookups.
///
/// The `Name` bar's denominator is the DISTINCT lookup count: endpoints
/// sharing a host share one query (the waiter fan-out), and unresolvable
/// names each run their own — so the bar completes exactly when the last
/// leader lookup finishes.
pub fn spawn_dns_retry(state: &mut AppState) {
    if state.maint_progress.is_some() {
        state.log_trace(
            "info",
            "tui::ops::compact",
            "Maintenance already running — start it again when the bars come down",
        );
        return;
    }
    let db = Arc::clone(&state.db);
    let purgatory_ttl_secs = state.purgatory_ttl_secs;
    let error_ttl_hours = state.config.speed_test.error_ttl_hours;
    let tx = state.core_event_tx.clone();
    let meters = install_meters(state);
    // ONLY the retry installs the enrich completion meter: a lookup bumping
    // `name.done` must not exist during a Compact run (which would show a
    // dead Name bar).
    crate::ops::enrich::set_resolve_progress(Some(Arc::clone(&meters.name)));
    let scan = meters.scan.clone();
    let name = meters.name.clone();
    tokio::spawn(async move {
        let rows = match load_all_rows(
            &db,
            purgatory_ttl_secs,
            error_ttl_hours,
            Some(scan.as_ref()),
        )
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                if let Some(tx) = &tx {
                    let _ = tx.try_send(crate::types::CoreEvent::CompactFinished {
                        merged: 0,
                        text: format!("DNS retry scan failed: {e}"),
                    });
                }
                return;
            }
        };
        let targets: Vec<(i64, String, Option<String>)> = rows
            .iter()
            .filter(|row| row.endpoint.is_dns() && row.resolved_ips.is_empty())
            .filter_map(|row| {
                let host = row.endpoint.dns_name();
                (!host.is_empty()).then(|| (row.endpoint.id.get(), host, row_sni(row)))
            })
            .collect();
        // Distinct leader lookups = distinct shared-host keys + one per
        // unresolvable name (those bypass the dedup by construction).
        let mut keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut solo = 0usize;
        for (_, host, _) in &targets {
            if crate::ops::enrich::is_resolvable_hostname(host) {
                keys.insert(crate::ops::enrich::lookup_key(host));
            } else {
                solo += 1;
            }
        }
        name.total.store((keys.len() + solo) as u32, Relaxed);
        if let Some(tx) = &tx {
            let _ = tx.try_send(crate::types::CoreEvent::DnsRetryTargets { targets });
        }
        // The terminal marker: the name bar completes when the last leader
        // lookup's task bumps `done`. Bounded, so a lost bump (a panicked or
        // reaped task) cannot strand the bar; the maintenance handler clears
        // the meters and logs on this event.
        for _ in 0..3600 {
            if name.done.load(Relaxed) >= name.total.load(Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if let Some(tx) = &tx {
            let _ = tx.try_send(crate::types::CoreEvent::MaintenanceDone);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::profiles::test_support::test_state;
    use leas_db::models::{
        Endpoint, HostType, Latency, ProfileStats, Protocol, ProtocolId, TrafficStats,
    };
    use std::time::Duration;
    use toasty::Deferred;

    fn vless_row(id: i64) -> Protocol {
        crate::ops::profiles::leas_db_helper::vless_protocol(id)
    }

    fn dns_endpoint_row(id: i64) -> Endpoint {
        Endpoint {
            id: EndpointId::new(id),
            domain: Endpoint::derive_domain("srv.example", HostType::Dns).0,
            sub_domain: Endpoint::derive_domain("srv.example", HostType::Dns).1,
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: Some(0),
            created_at: 0,
            links: Deferred::default(),
            group_links: Deferred::default(),
        }
    }

    fn ip_endpoint_row(id: i64, port: u16, ports: Vec<u16>) -> Endpoint {
        Endpoint {
            id: EndpointId::new(id),
            domain: String::new(),
            sub_domain: String::new(),
            port,
            ports,
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: 0,
            links: Deferred::default(),
            group_links: Deferred::default(),
        }
    }

    fn link(endpoint_id: i64, protocol_id: i64) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(protocol_id),
            endpoint_id: EndpointId::new(endpoint_id),
            last_used_at: None,
            last_seen_at: 0,
            latency: Latency::default(),
            speed_bps: None,
            error: None,
            purge_reason: None,
            stab_mask: 0,
            stab_len: 0,
            traffic: TrafficStats {
                today_up: 0,
                today_down: 0,
                total_up: 0,
                total_down: 0,
            },
            created_at: 0,
            updated_at: 0,
            version: 1,
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    async fn endpoint_count(db: &leas_db::Database) -> usize {
        Endpoint::all()
            .exec(&mut db.connection().await.unwrap())
            .await
            .unwrap()
            .len()
    }

    fn log_text(state: &AppState) -> String {
        state
            .log_cache
            .iter()
            .map(|l| l.message.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn poll_until(state: &mut AppState, needle: &str) -> String {
        for _ in 0..600 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = state.poll_core_events().await;
            if log_text(state).contains(needle) {
                break;
            }
        }
        log_text(state)
    }

    async fn seed_pair(db: &leas_db::Database, ip_ports: Vec<u16>) {
        db.upsert_endpoint(&dns_endpoint_row(1)).await.unwrap();
        db.upsert_endpoint(&ip_endpoint_row(2, 443, ip_ports))
            .await
            .unwrap();
        db.upsert_protocol(&vless_row(1001)).await.unwrap();
        db.upsert_link(&link(1, 1001)).await.unwrap();
        let mut l2 = link(2, 1001);
        l2.latency = Latency::fast(42);
        db.upsert_link(&l2).await.unwrap();
        let mut conn = db.connection().await.unwrap();
        leas_db::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[
                (EndpointId::new(1), "1.2.3.4".parse().unwrap()),
                (EndpointId::new(2), "1.2.3.4".parse().unwrap()),
            ],
        )
        .await
        .unwrap();
    }

    /// End to end on a seeded temp database: the pair collapses into the DNS
    /// survivor, the report lands in the actions log, and the meters come
    /// down with the terminal event.
    #[tokio::test]
    async fn compact_merges_seeded_duplicates_and_reports() {
        let mut state = test_state(vec![]).await;
        seed_pair(&state.db, vec![8443]).await;

        spawn_compact(&mut state);
        assert!(state.maint_progress.is_some(), "meters installed at spawn");
        let text = poll_until(&mut state, "Compact:").await;
        assert_eq!(endpoint_count(&state.db).await, 1, "the pair collapses");
        assert!(
            text.contains("Compact: 1 endpoint(s) merged"),
            "got: {text}"
        );
        assert!(state.maint_progress.is_none(), "meters cleared on terminal");
        let eps: Vec<Endpoint> = Endpoint::all()
            .exec(&mut state.db.connection().await.unwrap())
            .await
            .unwrap();
        assert_eq!(eps[0].ports, vec![443, 8443], "multi-port union");
    }

    /// The negative case that motivated the overlap criterion: a FLEET of
    /// endpoints reusing one credential on one port with DISJOINT address
    /// sets must produce ZERO merges — shared `protocol_id` alone can never
    /// identify a server.
    #[tokio::test]
    async fn compact_never_merges_a_disjoint_fleet() {
        let mut state = test_state(vec![]).await;
        let db = std::sync::Arc::clone(&state.db);
        db.upsert_protocol(&vless_row(1001)).await.unwrap();
        let mut conn = db.connection().await.unwrap();
        for id in 1..=3i64 {
            db.upsert_endpoint(&ip_endpoint_row(id, 443, vec![]))
                .await
                .unwrap();
            db.upsert_link(&link(id, 1001)).await.unwrap();
        }
        leas_db::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[
                (EndpointId::new(1), "10.0.0.1".parse().unwrap()),
                (EndpointId::new(2), "10.0.0.2".parse().unwrap()),
                (EndpointId::new(3), "10.0.0.3".parse().unwrap()),
            ],
        )
        .await
        .unwrap();
        drop(conn);

        spawn_compact(&mut state);
        let text = poll_until(&mut state, "Compact:").await;
        assert_eq!(endpoint_count(&state.db).await, 3, "disjoint survive");
        assert!(text.contains("no duplicate endpoints found"), "got: {text}");
    }

    /// A chain of aliases (A≈B, B≈C, A≁C) collapses into ONE survivor in a
    /// single run — the connected-component plan, not pairwise iteration.
    #[tokio::test]
    async fn compact_collapses_an_alias_chain() {
        let mut state = test_state(vec![]).await;
        let db = std::sync::Arc::clone(&state.db);
        db.upsert_endpoint(&dns_endpoint_row(1)).await.unwrap();
        db.upsert_endpoint(&ip_endpoint_row(2, 443, vec![]))
            .await
            .unwrap();
        db.upsert_endpoint(&ip_endpoint_row(3, 443, vec![]))
            .await
            .unwrap();
        db.upsert_protocol(&vless_row(1001)).await.unwrap();
        db.upsert_link(&link(1, 1001)).await.unwrap();
        db.upsert_link(&link(2, 1001)).await.unwrap();
        db.upsert_link(&link(3, 1001)).await.unwrap();
        let mut conn = db.connection().await.unwrap();
        leas_db::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[
                (EndpointId::new(1), "1.1.1.1".parse().unwrap()),
                (EndpointId::new(2), "1.1.1.1".parse().unwrap()),
                (EndpointId::new(2), "2.2.2.2".parse().unwrap()),
                (EndpointId::new(3), "2.2.2.2".parse().unwrap()),
            ],
        )
        .await
        .unwrap();
        drop(conn);

        spawn_compact(&mut state);
        poll_until(&mut state, "Compact:").await;
        assert_eq!(endpoint_count(&state.db).await, 1, "the chain collapses");
        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .unwrap();
        let mut set: Vec<String> = resolved
            .values()
            .flatten()
            .map(|(ip, _)| ip.to_string())
            .collect();
        set.sort();
        assert_eq!(set, vec!["1.1.1.1", "2.2.2.2"], "both addresses land");
    }

    /// Only DNS endpoints with an EMPTY address set are dispatched; IP
    /// literals and resolved hosts are not. The Name bar's total is the
    /// DISTINCT lookup count, and the run reports completion when it fills.
    #[tokio::test]
    async fn retry_targets_only_unresolved_dns_hosts() {
        let mut state = test_state(vec![]).await;
        let db = std::sync::Arc::clone(&state.db);
        db.upsert_endpoint(&dns_endpoint_row(1)).await.unwrap();
        db.upsert_endpoint(&ip_endpoint_row(2, 443, vec![]))
            .await
            .unwrap();
        let mut resolved = dns_endpoint_row(3);
        resolved.domain = Endpoint::derive_domain("ok.example", HostType::Dns).0;
        db.upsert_endpoint(&resolved).await.unwrap();
        db.upsert_protocol(&vless_row(1001)).await.unwrap();
        db.upsert_link(&link(1, 1001)).await.unwrap();
        db.upsert_link(&link(2, 1001)).await.unwrap();
        db.upsert_link(&link(3, 1001)).await.unwrap();
        let mut conn = db.connection().await.unwrap();
        leas_db::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[(EndpointId::new(3), "5.6.7.8".parse().unwrap())],
        )
        .await
        .unwrap();
        drop(conn);

        spawn_dns_retry(&mut state);
        let meters = state.maint_progress.clone().expect("meters installed");
        let text = poll_until(&mut state, "DNS retry:").await;
        assert!(
            text.contains("DNS retry: 1 endpoint(s) dispatched"),
            "exactly the one unresolved DNS host dispatched, got: {text}"
        );
        assert_eq!(
            meters.name.total.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // The completion marker arrives once the (bounded, single) lookup
        // finishes — this is a real resolver round-trip in the temp env
        // (up to the 8 s lookup deadline + the 500 ms poll step), so allow
        // generously rather than race the resolver.
        for _ in 0..1500 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = state.poll_core_events().await;
            if log_text(&state).contains("DNS retry: complete") {
                break;
            }
        }
        assert!(
            log_text(&state).contains("DNS retry: complete"),
            "the terminal event must arrive after the lookup settles"
        );
        assert!(
            state.maint_progress.is_none(),
            "meters come down at completion"
        );
    }
}
