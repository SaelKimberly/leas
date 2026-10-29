//! The batch `Speed Test (Successful)`: download a test file through each
//! successful link's own tunnel and persist the peak throughput.
//!
//! Modelled on `Fill Exit IPs` (`ping.rs::run_fill_exit_ips`): its own meters,
//! its own walk of one [`PlanScope`], and `CoreEvent::BatchEnded` as its
//! terminal event — but where the fill fetches an exit IP, this runs a
//! streaming download with the SAME failure contract as the real probe
//! (`ping_native::speed_ping`), so a failed download is categorized, marked
//! and purged exactly like a failed Real Test.
//!
//! The download rides the row's OWN native tunnel (dial → security → transport
//! → protocol), not the local SOCKS5 inbound: no loopback hop in the
//! measurement, and no need for the connected core.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use leas_core::speed_test::TestType;
use leas_db::Database;
use leas_db::models::{Endpoint, PurgatoryView};
use leas_db::profiles_query::{PageRequest, PageSort, PlanScope};
use tokio::sync::{Semaphore, mpsc};

use crate::AppState;
use crate::ops::ping_native::{self, NativeSpeedReq, ProbeClass};
use crate::try_send_or_warn;
use crate::types::{BatchMeters, CoreEvent};

/// Start the batch speed test over `scope`.
pub fn start_speed_test_batch(state: &mut AppState, scope: PlanScope) {
    // Its own slot, exactly like the fill: a batch running at the same time
    // would fight this one for the single bar.
    if state.batch_progress.is_some() || state.fill_progress.is_some() {
        state.log_trace("warn", "tui::ops::speed_test", "A batch is already running");
        return;
    }
    state.speed_test_stop.store(false, Ordering::Relaxed);
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let db = state.db.clone();
    let writer = state.link_stage.clone();
    let stop = state.speed_test_stop.clone();
    let speed = &state.config.speed_test;
    let timeout = *speed.real_ping_timeout_secs;
    let transport_timeout = *speed.tcp_timeout_secs;
    let max_duration = *speed.speed_test_max_duration;
    let min_duration = *speed.speed_test_min_duration;
    let min_bytes = speed.speed_test_min_bytes;
    let retries = speed.speed_test_retries;
    let speed_url = speed.speed_test_url.clone();
    let concurrency = speed.speed_test_concurrency.max(1);
    let meters = Arc::new(BatchMeters::default());
    state.batch_progress = Some(Arc::clone(&meters));
    tokio::spawn(run_speed_batch(SpeedBatchParams {
        db,
        writer,
        tx,
        stop,
        meters,
        scope,
        timeout,
        transport_timeout,
        max_duration,
        min_duration,
        min_bytes,
        retries,
        speed_url,
        concurrency,
    }));
}

struct SpeedBatchParams {
    db: Arc<Database>,
    writer: Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    tx: mpsc::Sender<CoreEvent>,
    stop: Arc<AtomicBool>,
    meters: Arc<BatchMeters>,
    scope: PlanScope,
    timeout: Duration,
    transport_timeout: Duration,
    max_duration: Duration,
    min_duration: Duration,
    min_bytes: u64,
    retries: u32,
    speed_url: String,
    concurrency: usize,
}

/// Run the batch: plan the scope's links once, then download through each
/// link's own tunnel under a bounded semaphore.
async fn run_speed_batch(params: SpeedBatchParams) {
    let SpeedBatchParams {
        db,
        writer,
        tx,
        stop,
        meters,
        scope,
        timeout,
        transport_timeout,
        max_duration,
        min_duration,
        min_bytes,
        retries,
        speed_url,
        concurrency,
    } = params;
    // The scope's endpoints, read once and frozen: the scope predicate reads
    // `rank_bin`, which this very batch rewrites as its results land, so an
    // offset-paged walk over the live predicate would skip rows (the same law
    // `PlanWalk` follows).
    let request = PageRequest {
        view: PurgatoryView::All,
        active_threshold: 0,
        scope,
        search: None,
        group_id: None,
        sort: PageSort::Test,
        ascending: true,
        offset: 0,
        limit: usize::MAX,
    };
    let page = match db.profiles_page(&request).await {
        Ok(page) => page,
        Err(e) => {
            tracing::warn!(target: "tui::ops::speed_test", "speed batch: plan failed: {e}");
            let _ = tx.try_send(CoreEvent::BatchEnded);
            return;
        }
    };
    let rows = match db.load_page_projection(&page.ids, false).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(target: "tui::ops::speed_test", "speed batch: load failed: {e}");
            let _ = tx.try_send(CoreEvent::BatchEnded);
            return;
        }
    };
    // One unit of work per link of the scope's endpoints — the same
    // projection the fill walks.
    let plans: Vec<(
        leas_db::models::ProfileStats,
        Endpoint,
        Vec<std::net::IpAddr>,
    )> = rows
        .iter()
        .flat_map(|r| {
            let endpoint = r.endpoint.clone();
            let addresses = r.resolved_ips.clone();
            r.links
                .iter()
                .cloned()
                .map(move |link| (link, endpoint.clone(), addresses.clone()))
        })
        .collect();
    let total = plans.len() as u32;
    meters.main.total.store(total, Ordering::Relaxed);
    let failed = Arc::new(AtomicU32::new(0));
    let failed_classes: Arc<parking_lot::Mutex<std::collections::BTreeMap<ProbeClass, u32>>> =
        Arc::new(parking_lot::Mutex::new(std::collections::BTreeMap::new()));
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    for (link, endpoint, addresses) in plans {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let permit = Arc::clone(&sem);
        let db = Arc::clone(&db);
        let writer = Arc::clone(&writer);
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let failed_classes = Arc::clone(&failed_classes);
        let failed = Arc::clone(&failed);
        let meters = Arc::clone(&meters);
        let speed_url = speed_url.clone();
        tasks.spawn(async move {
            let _permit = permit.acquire_owned().await;
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let failed_class = run_one_speed_probe(
                &db,
                &tx,
                &writer,
                &link,
                &endpoint,
                &addresses,
                &speed_url,
                timeout,
                transport_timeout,
                max_duration,
                min_duration,
                min_bytes,
                retries,
            )
            .await;
            if let Some(class) = failed_class {
                failed.fetch_add(1, Ordering::Relaxed);
                *failed_classes.lock().entry(class).or_default() += 1;
            }
            meters.main.done.fetch_add(1, Ordering::Relaxed);
        });
    }
    while tasks.join_next().await.is_some() {}
    // The writer flushes the staged rows; the terminal event closes the bar.
    let _ = writer.flush().await;
    let done = meters.main.done.load(Ordering::Relaxed);
    let failed_count = failed.load(Ordering::Relaxed);
    let _ = tx.try_send(CoreEvent::BatchEnded);
    let histogram = {
        let map = failed_classes.lock();
        let parts: Vec<String> = map
            .iter()
            .map(|(class, n)| format!("{}={n}", class.label()))
            .collect();
        drop(map);
        if parts.is_empty() {
            String::new()
        } else {
            format!(" failed[{}]", parts.join(" "))
        }
    };
    tracing::info!(
        target: "tui::ops::speed_test",
        "speed batch: {done}/{total} link(s) processed, {} ok, {failed_count} failed{histogram}",
        done.saturating_sub(failed_count),
    );
}

/// Run one link's download speed test. Returns the failure's CLASS on failure
/// (`None` on success) so the batch's summary histogram can count it — the
/// same role `ProbeOutcome.class` plays for the real batch's `probe_fail`.
async fn run_one_speed_probe(
    db: &Arc<Database>,
    tx: &mpsc::Sender<CoreEvent>,
    writer: &Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    link: &leas_db::models::ProfileStats,
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    speed_url: &str,
    timeout: Duration,
    transport_timeout: Duration,
    max_duration: Duration,
    min_duration: Duration,
    min_bytes: u64,
    retries: u32,
) -> Option<ProbeClass> {
    // The protocol row WITH its config — the engine is built from it and the
    // capability gate reads it.
    let Some(protocol) = crate::state::load_protocol_with_config(db, link.protocol_id)
        .await
        .ok()
        .flatten()
    else {
        let outcome = ProbeOutcome::soft_failure("Protocol row not found for speed test");
        let class = outcome.failed_class();
        settle(tx, writer, link, &outcome, None);
        return class;
    };
    let config = protocol.config.get().0.clone();
    // The config-level capability gate: its marker IS the result, exactly as
    // in the real probe.
    if let Some(reason) = leas_native::capability::support_reason(protocol.proto_kind, &config) {
        let outcome = ProbeOutcome::soft_failure(crate::ops::ping::untestable_marker_text(&reason));
        let class = outcome.failed_class();
        settle(tx, writer, link, &outcome, None);
        return class;
    }
    let result = ping_native::speed_ping(
        endpoint,
        addresses,
        &config,
        &NativeSpeedReq {
            speed_url,
            timeout,
            transport_timeout,
            max_duration,
            min_duration,
            min_bytes,
            retries,
        },
    )
    .await;
    let outcome = match result {
        Ok(r) => ProbeOutcome::Ok {
            speed_bps: r.peak_bytes_per_sec.saturating_mul(8),
            transport_ms: r.transport_ms,
            auth_ack: r.auth_ack,
        },
        Err(e) => ProbeOutcome::Failed {
            text: e.text,
            class: e.class,
            evidence: e.evidence,
            transport_ms: e.transport_ms,
            transport_failed: e.transport_failed,
            auth_ack: e.auth_ack,
        },
    };
    let class = outcome.failed_class();
    settle(tx, writer, link, &outcome, protocol.security.fp.as_deref());
    class
}

/// The outcome of one speed probe: the success carries the peak rate, the
/// failure carries the real probe's full taxonomy.
enum ProbeOutcome {
    Ok {
        speed_bps: u64,
        transport_ms: Option<u64>,
        auth_ack: leas_native::protocol::AuthAck,
    },
    Failed {
        text: String,
        class: ProbeClass,
        evidence: Option<leas_native::error::FailureEvidence>,
        transport_ms: Option<u64>,
        transport_failed: bool,
        auth_ack: leas_native::protocol::AuthAck,
    },
}

impl ProbeOutcome {
    /// The failure's class, for the batch's summary histogram; `None` on
    /// success (there is nothing to count).
    const fn failed_class(&self) -> Option<ProbeClass> {
        match self {
            Self::Ok { .. } => None,
            Self::Failed { class, .. } => Some(*class),
        }
    }
    /// A failure that proves nothing (the probe never ran): the marker text
    /// is what the row shows.
    fn soft_failure(text: impl Into<String>) -> Self {
        Self::Failed {
            text: text.into(),
            class: ProbeClass::Config,
            evidence: None,
            transport_ms: None,
            transport_failed: false,
            auth_ack: leas_native::protocol::AuthAck::NotApplicable,
        }
    }
}

/// Persist the row and emit the result event — the same two steps the batch's
/// `stage_result`/`emit_result` pair performs, with `TestType::SpeedTest` so
/// `apply_test_result` writes `speed_bps` and clears the verdict on success.
///
/// `speed_bps` is the peak 1-second-windowed rate in BITS per second (the
/// column's unit); the bytes→bits conversion happens once, in
/// `run_one_speed_probe`, at the engine boundary.
fn settle(
    tx: &mpsc::Sender<CoreEvent>,
    writer: &Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    link: &leas_db::models::ProfileStats,
    outcome: &ProbeOutcome,
    // The protocol row's security fingerprint: an approximated fingerprint
    // suppresses the purge verdict — the same rule the real probe's `purge_for`
    // applies (a dial on a roster-mapped row proves nothing about the config
    // the row ASKED for).
    fp: Option<&str>,
) {
    let (speed_bps, transport_ms, error, purge, marker_kind, auth_ack) = match outcome {
        ProbeOutcome::Ok {
            speed_bps,
            transport_ms,
            auth_ack,
        } => (Some(*speed_bps), *transport_ms, None, None, None, *auth_ack),
        ProbeOutcome::Failed {
            text,
            evidence,
            transport_ms,
            transport_failed,
            auth_ack,
            ..
        } => (
            None,
            *transport_ms,
            Some(text.clone()),
            // The purge verdict comes from the typed evidence, exactly as the
            // real probe's does (`purge_for` in ping.rs). The security
            // fingerprint is the row's own; a speed probe carries the same
            // row, so it is read here, not from a second source.
            evidence.and_then(|ev| crate::ops::purge::reason_for(ev, fp)),
            // A TRANSPORT-stage failure is the `[fast]` marker even though
            // this was a download (spec D1's "not measurable" outcome).
            transport_failed.then_some(leas_db::models::ProfileErr::Fast),
            *auth_ack,
        ),
    };
    let mut row = link.clone();
    if let Some(groups) = crate::ops::events::apply_test_result(
        &mut row,
        TestType::SpeedTest,
        None,
        transport_ms,
        speed_bps,
        None,
        error.as_deref(),
        purge,
        marker_kind,
        Some(auth_ack),
    ) {
        writer.stage(&row, groups);
    }
    let endpoint_id = link.endpoint_id.get();
    let _ = tx.try_send(CoreEvent::TestTypeUpdate {
        endpoint_id,
        protocol_id: link.protocol_id.get(),
        test_type: TestType::SpeedTest,
    });
    try_send_or_warn(
        tx,
        CoreEvent::SpeedTestResult {
            endpoint_id,
            protocol_id: link.protocol_id.get(),
            test_type: TestType::SpeedTest,
            latency_ms: None,
            transport_ms,
            speed_bps,
            ip_info: None,
            error,
            purge,
            marker_kind,
            auth_ack: Some(auth_ack),
        },
        "speed_test_result",
    );
}
