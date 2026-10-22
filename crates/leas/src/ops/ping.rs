use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use leas_config::IpProvider;
use leas_core::speed_test::TestType;
use leas_db::Database;
use leas_db::LinkGroups;
use leas_db::models::Protocol as DbProtocol;
use leas_db::models::{
    Endpoint, EndpointId, EndpointRow, ProfileStats, ProtocolId, PurgatoryView, TaskKind,
};
use leas_db::profiles_query::{PageRequest, PageSort, PlanScope};
use leas_native::capability;
use leas_proto::proto_spec::ProtocolConfig;
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::AppState;
use crate::ops::ping_native::{self, NativeProbeReq, ProbeClass};
use crate::ops::profiles::PROFILES_PAGE_SIZE;
use crate::ops::scheduler::{ScheduleOutcome, TaskScheduler};
use crate::state::load_protocol_with_config;
use crate::try_send_or_warn;
use crate::types::CoreEvent;

/// Perf lab for the fast + real flow (the cost lab, not a test; see the module
/// docs). `test` is part of the gate because the lab drives test-only helpers
/// and the `tempfile` dev-dependency, so it can only exist in the test unit.
#[cfg(all(test, feature = "perf-lab"))]
mod flow_cost;
#[cfg(all(test, feature = "perf-lab"))]
mod geo_batched_probe;

/// Bound on concurrent single-test tasks (menu-triggered pings): the spawned
/// future parks on this permit before doing work, so rapid keypresses queue
/// as tiny futures instead of spawning unbounded concurrent cores. Batch
/// paths already gate through their own semaphore/JoinSet.
static SINGLE_TEST_SEMAPHORE: std::sync::LazyLock<Semaphore> =
    std::sync::LazyLock::new(|| Semaphore::new(16));

/// The code default for `speed_test.real_ping_concurrency`
/// (`default_real_ping_concurrency` in `leas-config`), repeated because the
/// warning below is only actionable against it — the config file's own value is
/// what a stale override silently replaces.
/// First re-entry poll for a DNS-deferred half; it doubles up to the deferral
/// window. The window is the MAXIMUM wait, never the poll interval: a flat
/// short poll would be ~60 gate acquisitions per deferred half, and with
/// 1,577 deferred halves ~95k spurious dispatches per batch.
const DEFER_POLL_MIN: Duration = Duration::from_millis(250);

const REAL_CONCURRENCY_DEFAULT: u32 = 100;

/// Below this, a real phase is throughput-bound rather than feed-bound. A real
/// probe holds one slot for a dial plus (on failure) the whole timeout, so the
/// rate is roughly `concurrency / timeout`: the 2026-09-16 run measured 2.45
/// results/s at 5 (3,381 results in 23 min), i.e. ~4 h for a 34k-link plan.
const REAL_CONCURRENCY_WARN_BELOW: u32 = 50;

/// Prefix of the persisted marker text for a row the native engine cannot test.
///
/// The marker is a [`leas_db::models::ProfileErr::Real`] — the only failure
/// kind the frozen `error_kind` CHECK accepts (a new variant would be a schema
/// wipe, decision 4) — so the TEXT is the discriminator. One writer
/// ([`untestable_marker_text`]) and one reader ([`is_untestable_marker`], used
/// by the Test-cell precedence and by the Remove-Bad-Servers guard).
pub const UNTESTABLE_PREFIX: &str = "not testable by the native engine: ";

/// The persisted marker text for a link the native engine cannot test.
#[must_use]
pub fn untestable_marker_text(reason: &str) -> String {
    format!("{UNTESTABLE_PREFIX}{reason}")
}

/// True when a persisted failure marker means "never attempted" (the native
/// engine cannot serve this row) rather than "the probe ran and failed".
#[must_use]
pub fn is_untestable_marker(error: &leas_db::models::ErrorInfo) -> bool {
    is_untestable_text(&error.text)
}

/// The text-level twin of [`is_untestable_marker`], for the paths that hold the
/// failure text before any row exists — the batch's counters.
///
/// One prefix check for both, so the marker's discriminator cannot drift between
/// the Test cell, the Remove-Bad-Servers guard and the counters.
#[must_use]
fn is_untestable_text(text: &str) -> bool {
    text.starts_with(UNTESTABLE_PREFIX)
}

/// A link counts as "failed" for the Remove-Bad-Servers sweep only when a probe
/// actually ran: the untestable marker says the native engine cannot serve the
/// row, and deleting a profile for that is wrong.
fn is_removable_failure(link: &ProfileStats) -> bool {
    link.error
        .as_ref()
        .is_some_and(|e| !is_untestable_marker(e))
}

/// Start TCP ping on the given profile. Returns immediately; result arrives via `CoreEvent`.
/// The row's plugin mode when a TCP fast probe would be meaningless — a
/// datagram-mode SIP003 row. `None` for every other row, including one that
/// merely mentions `mode=quic` in a spelling we resolve to something else.
fn datagram_plugin_mode(config: &ProtocolConfig) -> Option<String> {
    let ProtocolConfig::Ss(ss) = config else {
        return None;
    };
    let plugin = ss.plugin.as_ref()?;
    if plugin.tcp_fast_probe_is_meaningful() {
        return None;
    }
    Some(plugin.resolved_mode().as_str().to_string())
}

pub fn start_tcp_ping(state: &mut AppState, endpoint_id: i64, protocol_id: i64) {
    if state.testing_profiles.contains(&(endpoint_id, protocol_id)) {
        state.log_trace(
            "warn",
            "tui::ops::ping",
            "Test already in progress for this profile",
        );
        return;
    }
    // Find the profile and extract address:port. Lookup is by the
    // (endpoint, protocol) pair, never by protocol alone: a `Protocol` row is
    // shared across endpoints (identity dedup excludes host/port), so
    // first-owner resolution would probe and update the wrong server when two
    // endpoints share the same config.
    let Some(row) = state
        .endpoints
        .iter()
        .find(|r| r.endpoint.id.get() == endpoint_id)
    else {
        state.log_trace("error", "tui::ops::ping", "Endpoint not found for TCP ping");
        return;
    };
    let Some(link) = row
        .links
        .iter()
        .find(|l| l.protocol_id.get() == protocol_id)
    else {
        state.log_trace("error", "tui::ops::ping", "Protocol not found for TCP ping");
        return;
    };
    let Some(proto) = row.protocols.get(&link.protocol_id) else {
        state.log_trace(
            "error",
            "tui::ops::ping",
            "Protocol row not found for TCP ping",
        );
        return;
    };
    // §8.1 item 4: the fast level is protocol-KIND-blind — `FastPingManager`
    // picks `TcpPingAdapter` from `ProtocolKind` alone — so a datagram-mode
    // plugin row would be TCP-probed against a UDP port and the refusal booked
    // as a hard connect failure about a server that is perfectly alive. The menu
    // path and every other caller land here, so this is the ONE place the row's
    // own resolved mode has to be consulted.
    if let Some(mode) = datagram_plugin_mode(&proto.config.get().0) {
        state.log_trace(
            "warn",
            "tui::ops::ping",
            &format!(
                "No TCP fast probe for this row: shadowsocks plugin mode `{mode}` is a \
                 datagram transport, so a TCP connect proves nothing (spec 8.1 item 4)"
            ),
        );
        return;
    }
    let addr = dial_host(&row.endpoint, &row.resolved_ips);
    if addr.is_empty() {
        state.log_trace("error", "tui::ops::ping", "Profile has no address");
        return;
    }
    let port = if row.endpoint.port > 0 {
        row.endpoint.port
    } else {
        state.log_trace("error", "tui::ops::ping", "Profile has invalid port");
        return;
    };

    let tx = if let Some(tx) = &state.core_event_tx {
        tx.clone()
    } else {
        state.log_trace(
            "error",
            "tui::ops::ping",
            "Core event channel not initialized",
        );
        return;
    };

    // The fast-ping adapters dispatch on the protocol kind.
    let config_type = proto.proto_kind.to_i32();
    state
        .testing_details
        .insert((endpoint_id, protocol_id), TestType::TcpPing);
    state.testing_profiles.insert((endpoint_id, protocol_id));
    state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);
    let timeout_dur = *state.config.speed_test.tcp_timeout_secs;

    tokio::spawn(async move {
        let Ok(_permit) = SINGLE_TEST_SEMAPHORE.acquire().await else {
            return;
        };
        let fmgr = leas_core::FastPingManager::new(timeout_dur);
        let result = fmgr.ping(config_type, &addr, port).await;
        let (latency_ms, error) = match result {
            Ok(dur) => (Some(dur.as_millis() as u64), None),
            Err(e) => (None, Some(e.to_string())),
        };
        try_send_or_warn(
            &tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type: TestType::TcpPing,
                latency_ms,
                transport_ms: None,
                speed_bps: None,
                ip_info: None,
                error,
                purge: None,
                marker_kind: None,
            },
            "tcp_ping_result",
        );
    });
}

/// Start real ping (one HTTP probe through the native engine).
///
/// The `Protocol` row is re-loaded WITH its deferred `config` inside the
/// spawned task (the probe consumes the typed [`ProtocolConfig`]), then the
/// native capability gate decides between a probe and the persisted
/// "not testable" marker.
pub fn start_real_ping(state: &mut AppState, endpoint_id: i64, protocol_id: i64) {
    if state.testing_profiles.contains(&(endpoint_id, protocol_id)) {
        return;
    }

    // Resolve by the (endpoint, protocol) pair — see `start_tcp_ping` for why
    // protocol-only lookup is wrong for shared `Protocol` rows.
    let endpoint;
    let addresses;
    let protocol_id_typed;
    if let Some(r) = state
        .endpoints
        .iter()
        .find(|r| r.endpoint.id.get() == endpoint_id)
        && let Some(l) = r.links.iter().find(|l| l.protocol_id.get() == protocol_id)
    {
        endpoint = r.endpoint.clone();
        addresses = r.resolved_ips.clone();
        protocol_id_typed = l.protocol_id;
    } else {
        state.log_trace("error", "tui::ops::ping", "Profile not found for real ping");
        return;
    }

    let tx = match &state.core_event_tx {
        Some(tx) => tx.clone(),
        None => return,
    };
    state
        .testing_details
        .insert((endpoint_id, protocol_id), TestType::RealPing);
    state.testing_profiles.insert((endpoint_id, protocol_id));
    state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);

    let db = state.db.clone();

    let ping_url = state.config.speed_test.ping_url.clone();
    let ip_provider = state.config.speed_test.ip_provider;
    let timeout = *state.config.speed_test.real_ping_timeout_secs;
    let retries = state.config.speed_test.real_ping_retries;

    tokio::spawn(async move {
        let Ok(_permit) = SINGLE_TEST_SEMAPHORE.acquire().await else {
            return;
        };
        let _ = tx.try_send(CoreEvent::TestTypeUpdate {
            endpoint_id,
            protocol_id,
            test_type: TestType::RealPing,
        });

        // Load the protocol row WITH its config included (the config builders
        // and `shadowsocks_method` refuse unloaded configs).
        let protocol = match load_protocol_with_config(&db, protocol_id_typed).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::SpeedTestResult {
                        endpoint_id,
                        protocol_id,
                        test_type: TestType::RealPing,
                        latency_ms: None,
                        transport_ms: None,
                        speed_bps: None,
                        ip_info: None,
                        error: Some("Protocol row not found for real ping".to_string()),
                        purge: None,
                        marker_kind: None,
                    },
                    "real_ping_protocol_missing",
                );
                return;
            }
            Err(e) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::SpeedTestResult {
                        endpoint_id,
                        protocol_id,
                        test_type: TestType::RealPing,
                        latency_ms: None,
                        transport_ms: None,
                        speed_bps: None,
                        ip_info: None,
                        error: Some(format!("Failed to load protocol: {e}")),
                        purge: None,
                        marker_kind: None,
                    },
                    "real_ping_protocol_load",
                );
                return;
            }
        };

        let config = protocol.config.get().0.clone();
        // Native capability gate: a row the engine cannot serve fails fast with
        // the persisted `[real]` marker instead of a probe.
        if let Some(reason) = capability::support_reason(protocol.proto_kind, &config) {
            try_send_or_warn(
                &tx,
                CoreEvent::SpeedTestResult {
                    endpoint_id,
                    protocol_id,
                    test_type: TestType::RealPing,
                    latency_ms: None,
                    transport_ms: None,
                    speed_bps: None,
                    ip_info: None,
                    error: Some(untestable_marker_text(&reason)),
                    purge: None,
                    marker_kind: None,
                },
                "real_ping_untestable",
            );
            return;
        }

        let result = ping_native::real_ping(
            &endpoint,
            &addresses,
            &config,
            &NativeProbeReq {
                ping_url: &ping_url,
                ip_provider,
                timeout,
                transport_timeout: timeout,
                retries,
            },
        )
        .await;
        // The typed evidence the engine reported becomes the purge verdict —
        // the only place a single ping can earn one (the taxonomy lives in
        // `ops::purge`, never here).
        //
        // The TRANSPORT span rides along on BOTH arms: it is the Fast metric,
        // and it survives a failure — a row whose transport answered but whose
        // config did not says "the server is up, the config is not" (spec
        // D12).
        let (latency_ms, transport_ms, error, purge, marker_kind) = match result {
            Ok(r) => (Some(r.latency_ms), r.transport_ms, None, None, None),
            Err(e) => (
                None,
                e.transport_ms,
                Some(e.text),
                // The `security_fp` COLUMN from this site's own `Protocol` row
                // — the same input every other path reads.
                e.evidence.and_then(|ev| {
                    crate::ops::purge::reason_for(ev, protocol.security.fp.as_deref())
                }),
                // A TRANSPORT-stage failure is the `[fast]` marker even though
                // this was a real probe (spec D1's "not measurable" outcome):
                // the transport never came up, so the row is a transport
                // failure, not a config verdict.
                e.transport_failed
                    .then_some(leas_db::models::ProfileErr::Fast),
            ),
        };
        // The exit IP is a SEPARATE phase (spec D10/D11): the probe's verdict
        // never depends on it, and it ages on its own. A failed probe does
        // NOT fetch one — there is no proof the config works, so a tunnel
        // built from it would report the WRONG exit.
        let ip_info = if latency_ms.is_some() {
            match ping_native::parse_probe_url(&ping_url) {
                Ok(target) => {
                    let params = ping_native::probe_params(&endpoint, &addresses, &config, &target);
                    ping_native::fetch_exit_ip(&params, ip_provider).await
                }
                Err(_) => None,
            }
        } else {
            None
        };

        try_send_or_warn(
            &tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type: TestType::RealPing,
                latency_ms,
                transport_ms,
                speed_bps: None,
                ip_info,
                error,
                purge,
                marker_kind,
            },
            "real_ping_result",
        );
    });
}

/// Start speed test (download through proxy) on the given profile.
pub fn start_speed_test(state: &mut AppState, endpoint_id: i64, protocol_id: i64) {
    if state.testing_profiles.contains(&(endpoint_id, protocol_id)) {
        return;
    }
    if state.connected_core.is_none() {
        state.log_trace(
            "warn",
            "tui::ops::ping",
            "Core not connected — proxy required for speed test",
        );
        return;
    }
    let tx = match &state.core_event_tx {
        Some(tx) => tx.clone(),
        None => return,
    };
    state
        .testing_details
        .insert((endpoint_id, protocol_id), TestType::SpeedTest);
    state.testing_profiles.insert((endpoint_id, protocol_id));
    state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);
    let proxy_addr = state.config.inbound.listen.clone();
    let proxy_port = state.config.inbound.socks_port;
    let test_url = "http://cachefly.cachefly.net/1mb.test".to_string();
    let min_dur = std::time::Duration::from_secs(3);
    let max_dur = std::time::Duration::from_secs(10);

    tokio::spawn(async move {
        let Ok(_permit) = SINGLE_TEST_SEMAPHORE.acquire().await else {
            return;
        };
        let result =
            leas_core::speed_test::speed_test(&proxy_addr, proxy_port, &test_url, min_dur, max_dur)
                .await;
        let (speed_bps, error) = match result {
            Ok(bps) => (Some(bps), None),
            Err(e) => (None, Some(e.to_string())),
        };
        try_send_or_warn(
            &tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type: TestType::SpeedTest,
                latency_ms: None,
                transport_ms: None,
                speed_bps,
                ip_info: None,
                error,
                purge: None,
                marker_kind: None,
            },
            "speed_test_result",
        );
    });
}

/// Start UDP test through the connected proxy.
pub fn start_udp_test(state: &mut AppState, endpoint_id: i64, protocol_id: i64) {
    if state.testing_profiles.contains(&(endpoint_id, protocol_id)) {
        return;
    }
    if state.connected_core.is_none() {
        state.log_trace(
            "warn",
            "tui::ops::ping",
            "Core not connected — proxy required for UDP test",
        );
        return;
    }
    let tx = match &state.core_event_tx {
        Some(tx) => tx.clone(),
        None => return,
    };
    state
        .testing_details
        .insert((endpoint_id, protocol_id), TestType::UdpTest);
    state.testing_profiles.insert((endpoint_id, protocol_id));
    state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);
    let proxy_addr = state.config.inbound.listen.clone();
    let proxy_port = state.config.inbound.socks_port;

    tokio::spawn(async move {
        let Ok(_permit) = SINGLE_TEST_SEMAPHORE.acquire().await else {
            return;
        };
        let result = leas_core::speed_test::udp_test(
            &proxy_addr,
            proxy_port,
            std::time::Duration::from_secs(5),
        )
        .await;
        let (latency_ms, error) = match result {
            Ok(dur) => (Some(dur.as_millis() as u64), None),
            Err(e) => (None, Some(e.to_string())),
        };
        try_send_or_warn(
            &tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type: TestType::UdpTest,
                latency_ms,
                transport_ms: None,
                speed_bps: None,
                ip_info: None,
                error,
                purge: None,
                marker_kind: None,
            },
            "udp_test_result",
        );
    });
}

/// Signal all running tests to stop.
pub fn stop_speed_test(state: &mut AppState) {
    state.speed_test_stop.store(true, Ordering::Relaxed);
}

/// Remove endpoints whose links carry a persisted failure marker (the old
/// `extension.delay == Some(-1)` sweep, now driven by `ProfileStats.error`).
pub async fn remove_failed_servers(state: &mut AppState) {
    let to_remove: Vec<leas_db::models::EndpointId> = state
        .endpoints
        .iter()
        .filter(|r| r.links.iter().any(is_removable_failure))
        .map(|r| r.endpoint.id)
        .collect();
    let count = to_remove.len();
    if count > 0 {
        // ONE transaction for the whole sweep: the per-endpoint path opens a
        // transaction, re-scans for orphan protocols and prunes rank keys
        // every time, which is the wrong shape for "remove everything failed
        // on this page".
        match state.db.delete_endpoints(&to_remove).await {
            Ok(_) => state.log_trace(
                "info",
                "tui::ops::ping",
                &format!("Removed {count} failed server(s)"),
            ),
            Err(e) => state.log_trace(
                "error",
                "tui::ops::ping",
                &format!("Failed to remove failed servers: {e}"),
            ),
        }
        for id in &to_remove {
            state.multi_select.remove(&id.get());
        }
    }
    state.multi_select.clear();
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

// ══════════════════════════════════════════════════════════════════════════
// Batch pipeline (T19) — rebuilt on the TaskScheduler
// ══════════════════════════════════════════════════════════════════════════
//
// Phase 1 schedules one `FastPing` task per link; the fast probes are
// deduplicated by (address, port) — one TCP ping per unique address, the
// result fanned out to every link sharing it (the old `FastCache` semantics).
// It is bounded by `fast_ping_concurrency` (one probe future per unique
// address at a time). `DnsDeferred` links are re-scheduled after the deferral
// window in a spawned task; `QueueFull` links are skipped (the scheduler logs
// the warning).
// Phase 2 (after every phase-1 task settles) schedules one `RealPing` task per
// link on the native engine (`ops/ping_native.rs` with the protocol row
// reloaded WITH config). Links the native engine cannot serve are retired at
// plan time (kind gate) or by their own probe (config gate) and receive the
// persisted `[real]` marker instead of a probe — `emit_untestable_markers`
// runs after phase 1 so the marker is never cleared by a fast success. With
// `dedup_endpoints` (the `real_ping_test_all_protocols` negation), the first
// successful real ping on an endpoint retires the remaining links' real tasks
// via `scheduler.cancel_queued` + `complete` — cancelled tasks never write
// error markers. The scheduler is the single gate authority: probes run only
// for ids `schedule`/`complete` hand out, and every completion re-reads the
// link (stale snapshots are rejected by the scheduler).
//
// Batches are serialized (one at a time): the fire-handshake does not support
// two batches racing to fire promoted tasks on the same link, and the shared
// progress bar displays one batch.

/// Where a batch's plan comes from.
///
/// The "all" entry points test the FEED, not the viewport: the loaded page is
/// 200 endpoint rows, so a batch scoped to it tested 272 of the 4,523 links in
/// the 2026-09-15 feed while the user expected the whole database. Only links
/// that appear *after* the plan is built can be missed.
#[derive(Debug)]
enum PlanSource {
    /// Every link in the database, narrowed to a [`PlanScope`] of endpoints.
    Feed(PlanScope),
    /// An explicit plan: the selected-endpoint entry points, and tests.
    Links(Vec<PlanLink>),
}

/// One link in a batch plan: the scheduler identity (link snapshot), the
/// endpoint (probe target + dedup identity), and the protocol row snapshot
/// (fast config type; real probes load the row WITH config from the batch's
/// per-protocol cache).
///
/// The endpoint is shared (`Arc`) because a plan page carries the same endpoint
/// once per link of that endpoint, and `dispatch_page` hands it straight to the
/// per-batch map the probes read: one clone and one allocation per ENDPOINT,
/// not per link.
#[derive(Clone, Debug)]
struct PlanLink {
    link: ProfileStats,
    endpoint: Arc<Endpoint>,
    /// The endpoint's resolved addresses (db-rewamp D10): an IP host's literal
    /// lives here, not on the `Endpoint` row.
    addresses: Vec<std::net::IpAddr>,
    protocol: DbProtocol,
}

/// The host a probe dials: a DNS host's reconstructed name, an IP host's
/// literal from the address set (db-rewamp D10).
fn dial_host(endpoint: &Endpoint, addresses: &[std::net::IpAddr]) -> String {
    if endpoint.is_dns() {
        endpoint.dns_name()
    } else {
        addresses
            .first()
            .map(ToString::to_string)
            .unwrap_or_default()
    }
}

/// The order the feed walk probes in.
///
/// The decision-16 law, so the most reliable links go first (spec
/// `2026-10-01-static-config-weight-design`). This REPLACES ADR 0008's
/// `PageSort::Id`, which existed to give the walk an order no write could move.
/// That property is what the freeze in `PlanWalk::next_page` now restores by
/// other means: the ids are read once, up front, precisely because the order is
/// no longer stable.
const FEED_SORT: PageSort = PageSort::Test;

/// Outcome of one dispatched probe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeOutcome {
    Ok {
        latency_ms: Option<u64>,
        /// The TRANSPORT span in ms — the time to establish the endpoint's
        /// transport (spec D2). The Fast metric.
        transport_ms: Option<u64>,
        ip_info: Option<String>,
    },
    Failed {
        text: String,
        /// Why it failed, for the batch's per-class counters (see
        /// [`classify_fast_failure`] and [`ping_native::ProbeFailure`]).
        class: ProbeClass,
        /// The endpoint was unreachable at the transport level, so the real
        /// phase's probe cannot succeed either. Set only by the fast runner
        /// (see [`classify_fast_failure`]).
        hard: bool,
        /// What the failure PROVES, when the engine reported it. Set only by
        /// the real runner: a fast probe's TCP handshake proves nothing about
        /// the config, which is why no fast path can earn a purge verdict.
        evidence: Option<leas_native::error::FailureEvidence>,
        /// The TRANSPORT span in ms, when the transport stage completed before
        /// the failure. `None` when the transport stage itself failed.
        ///
        /// A failure that carries it says "the transport was alive, the config
        /// was not" (spec D12) — the merged row's whole point.
        transport_ms: Option<u64>,
        /// Whether the TRANSPORT stage itself failed — the connection never
        /// came up.
        ///
        /// An explicit flag, NOT a class test: the engine reports the stage-1
        /// deadline and the stage-2+ deadline as the SAME class (`Timeout`),
        /// so a class test would retire a working server whose protocol stage
        /// hung. The merged pipeline's "not measurable" outcome (spec D1)
        /// reads THIS.
        transport_failed: bool,
    },
}

impl ProbeOutcome {
    /// A failure the real phase must still probe (config, protocol-load and
    /// engine-capability failures; a real probe answers a different question).
    fn soft_failure(text: impl Into<String>) -> Self {
        Self::Failed {
            text: text.into(),
            class: ProbeClass::Config,
            hard: false,
            // Never evidence: this constructor is how "not testable by the
            // native engine" and the batch's own bookkeeping failures arrive,
            // and neither is a statement about the config's quality.
            evidence: None,
            transport_ms: None,
            // A config-level refusal is not a transport failure: the config
            // never got as far as a connection.
            transport_failed: false,
        }
    }
}

/// Windows' `WSAHOST_NOT_FOUND` — `GetAddrInfoW` could not resolve the name.
/// `std` leaves it `Uncategorized` (it is absent from its WSA table), and no
/// Unix `errno` reaches 11001, so the bare code identifies it unambiguously.
const WSA_HOST_NOT_FOUND: i32 = 11001;

/// Classify a fast probe's failure: the batch's class bucket plus whether the
/// proxy is unreachable at the transport level — the classes the real phase
/// cannot pass either, so phase 2 skips the link.
///
/// Connect-class `PingError`s are hard: a timeout, or an IO error that reports
/// a refused connection, a missing route, an unreachable network, or an
/// unresolvable host. Everything else stays probed — fd exhaustion, a
/// TLS-level IO error or a protocol-level failure is local or ambiguous, and
/// the fast adapter's `NotSupported`/`Other` classes say nothing about
/// reachability.
///
/// Classification reads [`leas_core::ping::IoFailure::kind`] first and the raw OS
/// code second,
/// because `io::Error`'s message is localized and matching it was correct in
/// exactly one locale: a Russian Windows reports a connect timeout as
/// `Попытка установить соединение была безуспешной… (os error 10060)`, which
/// matched no needle, fell through to `Io`, and marked 314 dead endpoints
/// SOFT — so the real level spent 51% of its slots probing hosts the fast
/// level had already proven unreachable. `std` folds the WSA codes onto
/// portable kinds (`WSAETIMEDOUT` → `TimedOut`, `WSAECONNREFUSED` →
/// `ConnectionRefused`, `WSAEHOSTUNREACH` → `HostUnreachable`,
/// `WSAENETUNREACH` → `NetworkUnreachable`), so the same decision now holds in
/// every locale. The text match survives only as a last resort, for an
/// adapter that hands over a message with no `io::Error` behind it.
fn classify_fast_failure(err: &leas_core::ping::PingError) -> (ProbeClass, bool) {
    use leas_core::ping::PingError;
    match err {
        PingError::Timeout(_) => (ProbeClass::Timeout, true),
        PingError::Io(io) => classify_io_failure(io.kind, io.raw_code, &io.text),
        PingError::NotSupported => (ProbeClass::Config, false),
        PingError::Other(_) => (ProbeClass::Other, false),
    }
}

/// The reachable/unreachable decision over the typed facts of an IO failure.
///
/// Split out from [`classify_fast_failure`] so it is a pure function of its
/// arguments: the regression it fixes was invisible to the test suite *because*
/// it depended on the host's OS message, and a pure function over `ErrorKind` +
/// code is testable on any platform, including the CI box that has never seen a
/// WSA error.
fn classify_io_failure(
    kind: Option<std::io::ErrorKind>,
    raw_code: Option<i32>,
    text: &str,
) -> (ProbeClass, bool) {
    use std::io::ErrorKind;
    // A name that does not resolve is decided before the kind match: Windows
    // reports `WSAHOST_NOT_FOUND` uncategorized, and an unresolvable host is a
    // DNS verdict whatever else the platform called it.
    if raw_code == Some(WSA_HOST_NOT_FOUND) {
        return (ProbeClass::Dns, true);
    }
    match kind {
        Some(ErrorKind::TimedOut) => (ProbeClass::Timeout, true),
        Some(ErrorKind::ConnectionRefused) => (ProbeClass::Refused, true),
        Some(ErrorKind::HostUnreachable) => (ProbeClass::NoRoute, true),
        Some(ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown) => {
            (ProbeClass::Unreachable, true)
        }
        // `NotFound` is what a resolver reports when std does map it; the
        // Windows code above covers the platforms that leave it uncategorized.
        Some(ErrorKind::NotFound) => (ProbeClass::Dns, true),
        // Nothing typed to classify on AND no OS code: the message never came
        // from `std::io`, it is an adapter's own text, so the historical
        // English match is the only signal left. An error that DOES carry a
        // code has already been decided above and is never re-read as text.
        None if raw_code.is_none() => classify_io_failure_text(text),
        // A code or kind this function has no verdict for: local resource
        // failures (fd exhaustion), a reset mid-exchange, a blocked datagram.
        // Classified, but not proof the endpoint is unreachable.
        _ => (ProbeClass::Io, false),
    }
}

/// Last-resort text classification, for adapter messages with no `io::Error`
/// behind them. English-only by construction: the whole reason
/// [`classify_io_failure`] exists is that this cannot be trusted as a primary
/// signal.
fn classify_io_failure_text(text: &str) -> (ProbeClass, bool) {
    if text.contains("failed to lookup address information")
        || text.contains("Name or service not known")
    {
        (ProbeClass::Dns, true)
    } else if text.contains("Connection refused") {
        (ProbeClass::Refused, true)
    } else if text.contains("No route to host") {
        (ProbeClass::NoRoute, true)
    } else if text.contains("Network is unreachable") {
        (ProbeClass::Unreachable, true)
    } else {
        (ProbeClass::Io, false)
    }
}

/// Probe execution seam. The production impl runs the real engines
/// ([`FastPingManager`] + the pooled core); tests stub it so the batch
/// pipeline is exercised hermetically.
trait BatchProbeRunner: Send + Sync {
    /// One fast probe for a unique (address, port) — the batch dedups calls.
    fn fast<'a>(
        &'a self,
        config_type: i32,
        addr: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;

    /// One real probe for a single link. `config` is the already-loaded
    /// [`ProtocolConfig`] — the caller gates on it before it gets here.
    fn real<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        addresses: &'a [std::net::IpAddr],
        config: &'a ProtocolConfig,
        req: NativeProbeReq<'a>,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;
}

/// Production runner: [`leas_core::FastPingManager`] for fast probes and
/// the in-process native engine ([`crate::ops::ping_native`]) for real probes.
///
/// The subprocess pool is gone: a real probe dials the native engine directly,
/// so there is no warm process to share and no `batch_active` flag to raise
/// against concurrent single pings.
struct EngineProbeRunner;

impl BatchProbeRunner for EngineProbeRunner {
    fn fast<'a>(
        &'a self,
        config_type: i32,
        addr: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
        Box::pin(async move {
            match leas_core::FastPingManager::new(timeout)
                .ping(config_type, addr, port)
                .await
            {
                Ok(dur) => ProbeOutcome::Ok {
                    latency_ms: Some(dur.as_millis() as u64),
                    // The fast probe IS a transport measurement: its span is
                    // the transport span (spec D2).
                    transport_ms: Some(dur.as_millis() as u64),
                    ip_info: None,
                },
                Err(e) => {
                    let (class, hard) = classify_fast_failure(&e);
                    ProbeOutcome::Failed {
                        class,
                        hard,
                        // The fast probe IS a transport measurement, so its
                        // hard failure is a transport failure by definition.
                        transport_failed: hard,
                        // The FULL `Display` of the error, not a compact
                        // summary: this string is both what the debug
                        // per-result line prints — the only place an
                        // unclassified failure is diagnosable — and what gets
                        // persisted. Storage is bounded and compacted at the
                        // boundary instead (`cap_error_text`), so the OS code
                        // survives while the row stays short. Compacting here
                        // would have removed the sentence from the log.
                        text: e.to_string(),
                        evidence: None,
                        transport_ms: None,
                    }
                }
            }
        })
    }

    fn real<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        addresses: &'a [std::net::IpAddr],
        config: &'a ProtocolConfig,
        req: NativeProbeReq<'a>,
    ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
        Box::pin(async move {
            match ping_native::real_ping(endpoint, addresses, config, &req).await {
                Ok(result) => {
                    // The exit IP is a SEPARATE phase (spec D10/D11): it rides
                    // its own tunnel, it never affects the probe's verdict, and
                    // a failed probe does not fetch one.
                    let ip_info = match ping_native::parse_probe_url(req.ping_url) {
                        Ok(target) => {
                            let params =
                                ping_native::probe_params(endpoint, addresses, config, &target);
                            ping_native::fetch_exit_ip(&params, req.ip_provider).await
                        }
                        Err(_) => None,
                    };
                    ProbeOutcome::Ok {
                        latency_ms: Some(result.latency_ms),
                        transport_ms: result.transport_ms,
                        ip_info,
                    }
                }
                Err(e) => ProbeOutcome::Failed {
                    text: e.text,
                    class: e.class,
                    hard: false,
                    evidence: e.evidence,
                    transport_ms: e.transport_ms,
                    transport_failed: e.transport_failed,
                },
            }
        })
    }
}

/// One protocol row as a real probe needs it: the kind (for the config-level
/// capability gate) and the typed config the engine is built from.
#[derive(Debug)]
struct LoadedProtocol {
    kind: leas_proto::proto_spec::ProtocolKind,
    config: ProtocolConfig,
    /// The `security_fp` COLUMN, captured once here.
    ///
    /// The purge rule's input is the column on every path — this is the row's
    /// own field, and this struct is built from that row, so the rule never
    /// reads a second source. Without it the two `self.protocols` call sites
    /// would have to reach the config instead, and "the gate, the label and the
    /// purge rule cannot disagree" would hold over the predicate but not over
    /// the input.
    fp: Option<String>,
}

/// Shared per-batch state, cloned into every spawned probe task.
///
/// `pub(crate)` because the quit path (`ui/mod.rs`) has to render the run's
/// summary: a batch cancelled by the runtime drop never reaches `finish_batch`,
/// which is how the 2026-09-16 run left 31k persisted results with no record of
/// the run.
pub(crate) struct BatchShared {
    sched: Arc<TaskScheduler>,
    db: Arc<Database>,
    /// Gate persistence seam: staged transitions, never a commit per call.
    writer: Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    tx: mpsc::Sender<CoreEvent>,
    runner: Arc<dyn BatchProbeRunner>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Live meters, the same `Arc` the UI renders (no progress event).
    meters: Arc<crate::types::BatchMeters>,
    /// The batch's clock: every span in the summary is measured from here.
    started: Instant,
    real_phase: bool,
    dedup_endpoints: bool,
    fast_timeout: Duration,
    real_timeout: Duration,
    /// The TRANSPORT stage's own budget — independent of `real_timeout`
    /// (spec `2026-10-21-merged-test-pipeline-design` D12).
    transport_timeout: Duration,
    real_retries: u32,
    ping_url: String,
    ip_provider: IpProvider,
    defer_delay: Duration,
    real_concurrency: usize,
    /// "Clear error after" (design §6.4): `None` = never sweep.
    error_ttl_hours: Option<i64>,
    /// The DNS-resolution cache TTL, the gate on the batch's resolve requests.
    dns_cache_ttl_secs: i64,
    /// Where `run_batch` publishes the batch's shared state — `AppState::batch`
    /// holds the same slot and the UI reads the summary through it.
    batch_slot: Arc<OnceLock<Arc<Self>>>,
    /// Fast config type per link (`proto_kind`), filled by the plan walk.
    fast_config: DashMap<(ProtocolId, EndpointId), i32>,
    /// Endpoint rows by id (real probes need the full endpoint). `Arc` so a
    /// probe clones the handle instead of holding a shard guard across an await.
    endpoints: DashMap<EndpointId, Arc<Endpoint>>,
    addrs: DashMap<EndpointId, Vec<std::net::IpAddr>>,
    /// Protocol rows WITH their config, loaded once per `ProtocolId` per batch.
    ///
    /// A `Protocol` row is shared by every endpoint carrying the same config
    /// (identity ignores host/port), and the real half used to reload it per
    /// LINK: a toasty query plus a JSON decode, measured at 67–121 µs, i.e.
    /// 0.6–1.1 s over the 9k-link reference feed and 2.3–4.1 s over a 34k-link
    /// plan. A load FAILURE is not cached, so a transient read error cannot
    /// poison the protocol for the rest of the run.
    protocols: DashMap<ProtocolId, Arc<LoadedProtocol>>,
    /// Links the native engine cannot serve (kind-level gate, no config load),
    /// keyed by identity and carrying the persisted marker text. The fast half
    /// still probes them; their marker is emitted right after that result.
    untestable: DashMap<(ProtocolId, EndpointId), String>,
    /// The ONE probe bound (`real_ping_concurrency`, spec D14).
    ///
    /// The fast level's own bound is retired: the merged pipeline's fast half
    /// is a TRANSPORT measurement taken by the probe itself, so the limit that
    /// matters is the one that bounds native handshakes — the expensive stage.
    real_sem: Arc<Semaphore>,
    // ── settle accounting ─────────────────────────────────────────────
    pending_fast: AtomicUsize,
    pending_real: AtomicUsize,
    /// Deferral retries in flight. A retry sleeps without holding a gate entry,
    /// so the two task counters cannot see it and `finish_batch` must not run
    /// while one is still waiting.
    pending_deferred: AtomicUsize,
    /// Woken on every settle: one `Notify` covers all three counters, and the
    /// waiter re-reads them.
    settled: Notify,
    /// Every spawned chain and retry, so the batch can join the lot before
    /// `finish_batch`. The counters say when work is *settled*; a chain is also
    /// running between its fast settle and its real dispatch, which no counter
    /// covers — the join is what makes the batch's end a hard boundary.
    tasks: Mutex<Vec<JoinHandle<()>>>,
    // ── rate sampling (1 Hz, for the ETA) ─────────────────────────────
    /// The one level's rate sample (the ETA's denominator).
    rate_main: Mutex<(Instant, u32)>,
    // ── fast-probe dedup: one TCP ping per unique (address, port) ─────
    fast_dedup: Mutex<FastDedupInner>,
    /// Links whose fast probe failed for a hard unreachability reason: their
    /// real half is not probed (the probe cannot pass where the dial did not).
    hard_fast: Mutex<HashSet<(ProtocolId, EndpointId)>>,
    /// The delay the fast level measured, per link, for as long as the batch
    /// runs.
    ///
    /// The RESULT group writes `latency` and `error` together and every patch
    /// is built from the plan-time snapshot, so a real patch would carry
    /// `latency = None` and wipe the measurement the same batch had just taken
    /// (160 of 218 real failures lost their fast delay on 2026-09-15). This is
    /// the one field that must be composed back in.
    fast_latency: Mutex<HashMap<(ProtocolId, EndpointId), i32>>,
    /// The batch's counters (see [`BatchCounters`]).
    counters: BatchCounters,
    /// Wall-clock marks of the two levels, in ms since `started`. The spans
    /// overlap by construction (that is the pipeline), which the summary says.
    plan_ms: AtomicU32,
    fast_started_ms: AtomicU32,
    fast_ended_ms: AtomicU32,
    real_started_ms: AtomicU32,
    real_ended_ms: AtomicU32,
    // ── real-level endpoint dedup: endpoints whose real ping succeeded ─
    completed_endpoints: Mutex<HashSet<i64>>,
    /// The group's SIBLINGS, held until the group's first protocol's verdict
    /// lands (spec D15/T3.1).
    ///
    /// The endpoint's first protocol is probed immediately; its siblings wait
    /// for that verdict. The endpoint SUCCEEDED → the whole group is dropped
    /// (no probe, no marker, no delay, no exit IP for any of its links); the
    /// endpoint did NOT succeed → the siblings are released and probed.
    ///
    /// A plain `HashMap`, not a bloom filter: the set is tiny (the measured
    /// real-success rate is 0.03%–1.7%, so a 74k-endpoint run holds tens of
    /// ids) and a membership test must be exact — a false positive would
    /// silently drop a working config.
    deferred_siblings: Mutex<HashMap<i64, Vec<ProfileStats>>>,
    /// DNS resolution requests already emitted by this batch. The plan walk
    /// dispatches pages sequentially, but the set belongs to the batch: a DNS
    /// endpoint can span page boundaries while its first request is still
    /// queued or in flight.
    resolve_requested: Mutex<HashSet<i64>>,
}

/// Per-batch counters, folded into ONE summary line at the end (per-result
/// lines moved to `debug` for the same reason: a batch's volume is not a log).
#[derive(Default)]
struct BatchCounters {
    fast_ok: AtomicU32,
    fast_hard_failed: AtomicU32,
    fast_soft_failed: AtomicU32,
    /// Fast-level failures by class (the reason `fast_hard_failed` /
    /// `fast_soft_failed` only count, never explain).
    fast_fail: Mutex<BTreeMap<ProbeClass, u32>>,
    /// Groups whose siblings were DROPPED (the endpoint's first protocol
    /// succeeded) and groups whose siblings were RELEASED (it did not).
    group_dropped: AtomicU32,
    group_released: AtomicU32,
    real_ok: AtomicU32,
    real_failed: AtomicU32,
    /// Real-level failures by class.
    real_fail: Mutex<BTreeMap<ProbeClass, u32>>,
    untestable: AtomicU32,
    /// Real halves retired because the fast level proved them unreachable.
    unreachable: AtomicU32,
    deferred: AtomicU32,
    queue_full: AtomicU32,
}

/// Which level of a link's life a deferral retry is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Half {
    Fast,
    Real,
}

impl Half {
    /// The half's name, for the one debug line a deferral writes.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Real => "real",
        }
    }
}

struct FastDedupInner {
    cache: HashMap<(String, u16), ProbeOutcome>,
    in_flight: HashMap<(String, u16), Arc<Notify>>,
}

/// Parameters for one batch run. Built by the entry points from `AppState`;
/// tests construct these directly with a stubbed runner.
pub(crate) struct BatchParams {
    scheduler: Arc<TaskScheduler>,
    db: Arc<Database>,
    /// Gate persistence seam (staged transitions).
    writer: Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    tx: mpsc::Sender<CoreEvent>,
    runner: Arc<dyn BatchProbeRunner>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    meters: Arc<crate::types::BatchMeters>,
    plan: PlanSource,
    real_phase: bool,
    dedup_endpoints: bool,
    fast_timeout: Duration,
    real_timeout: Duration,
    /// The TRANSPORT stage's own budget — independent of `real_timeout`
    /// (spec `2026-10-21-merged-test-pipeline-design` D12).
    transport_timeout: Duration,
    real_retries: u32,
    ping_url: String,
    ip_provider: IpProvider,
    defer_delay: Duration,
    real_concurrency: usize,
    /// Endpoints per plan page. Production uses [`PROFILES_PAGE_SIZE`]; tests
    /// drive the streaming walk with tiny pages.
    page_size: usize,
    /// "Clear error after" (design §6.4): `None` = never sweep.
    error_ttl_hours: Option<i64>,
    /// The DNS-resolution cache TTL the batch gates its resolve requests on.
    dns_cache_ttl_secs: i64,
    /// Where `run_batch` publishes the batch's shared state as soon as it is
    /// built — `AppState::batch` holds the same slot and the UI reads the
    /// summary through it.
    batch_slot: Arc<OnceLock<Arc<BatchShared>>>,
}

impl BatchShared {
    /// Build the shared state.
    ///
    /// The plan is deliberately NOT here: the walk fills `fast_config`,
    /// `endpoints`, `untestable` and the meters page by page, which is what lets
    /// the first probe start within one page instead of after the whole feed.
    fn new(p: BatchParams) -> Self {
        Self {
            sched: p.scheduler,
            db: p.db.clone(),
            writer: p.writer,
            tx: p.tx,
            runner: p.runner,
            stop: p.stop,
            meters: p.meters,
            started: Instant::now(),
            real_phase: p.real_phase,
            dedup_endpoints: p.dedup_endpoints,
            fast_timeout: p.fast_timeout,
            real_timeout: p.real_timeout,
            transport_timeout: p.transport_timeout,
            real_retries: p.real_retries,
            ping_url: p.ping_url,
            ip_provider: p.ip_provider,
            defer_delay: p.defer_delay,
            real_concurrency: p.real_concurrency,
            error_ttl_hours: p.error_ttl_hours,
            dns_cache_ttl_secs: p.dns_cache_ttl_secs,
            batch_slot: p.batch_slot,
            fast_config: DashMap::new(),
            endpoints: DashMap::new(),
            addrs: DashMap::new(),
            protocols: DashMap::new(),
            untestable: DashMap::new(),
            real_sem: Arc::new(Semaphore::new(p.real_concurrency.max(1))),
            pending_fast: AtomicUsize::new(0),
            pending_real: AtomicUsize::new(0),
            pending_deferred: AtomicUsize::new(0),
            settled: Notify::new(),
            tasks: Mutex::new(Vec::new()),
            rate_main: Mutex::new((Instant::now(), 0)),
            fast_dedup: Mutex::new(FastDedupInner {
                cache: HashMap::new(),
                in_flight: HashMap::new(),
            }),
            hard_fast: Mutex::new(HashSet::new()),
            fast_latency: Mutex::new(HashMap::new()),
            counters: BatchCounters::default(),
            plan_ms: AtomicU32::new(0),
            fast_started_ms: AtomicU32::new(0),
            fast_ended_ms: AtomicU32::new(0),
            real_started_ms: AtomicU32::new(0),
            real_ended_ms: AtomicU32::new(0),
            completed_endpoints: Mutex::new(HashSet::new()),
            deferred_siblings: Mutex::new(HashMap::new()),
            resolve_requested: Mutex::new(HashSet::new()),
        }
    }

    /// Links planned so far — the walk increments it with each dispatched link.
    fn plan_len(&self) -> u32 {
        self.meters.main.total.load(Ordering::Relaxed)
    }

    /// Spawn a task the batch must outlive (chains and deferral retries).
    fn spawn_tracked(self: &Arc<Self>, fut: impl Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(fut);
        self.tasks.lock().push(handle);
    }

    /// Record the first start of a level, in ms since the batch began (the
    /// first writer wins: `0` means "not started yet").
    fn mark_started(&self, at: &AtomicU32) {
        let ms = u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX);
        let _ = at.compare_exchange(0, ms, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Record a level's latest settle.
    fn mark_settled(&self, at: &AtomicU32) {
        at.store(
            u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX),
            Ordering::Relaxed,
        );
    }

    /// One settle on a level: `done += 1`, plus a rate sample at most once a
    /// second (`results/s × 1000`, the render path's ETA input).
    ///
    /// The sample is taken on the settle that crosses the second boundary — no
    /// timer, no thread, and no per-result event.
    fn bump(phase: &crate::types::PhaseMeters, slot: &Mutex<(Instant, u32)>) {
        let done = phase.done.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = slot.lock();
        if done == 1 {
            // First result of this level: time the window from HERE. A slot
            // created with the batch would include the idle stretch before the
            // level's first settle — the live run of the fast+real pipeline (46
            // real results in 8 s) sampled 1 result over ~5 s of that idle
            // stretch, stored 0/s, and pinned the real ETA at `--` because no
            // later settle crossed a fresh second boundary.
            *last = (Instant::now(), done);
            return;
        }
        let elapsed = last.0.elapsed();
        if elapsed < Duration::from_secs(1) {
            return;
        }
        let elapsed_ms = u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let delta = u64::from(done.saturating_sub(last.1));
        // `rate_milli` is results/s × 1000 (`PhaseMeters::eta_secs` divides by
        // it), so a delta over `elapsed_ms` scales by 1e6, not 1e3.
        phase.rate_milli.store(
            u32::try_from(delta * 1_000_000 / elapsed_ms).unwrap_or(u32::MAX),
            Ordering::Relaxed,
        );
        *last = (Instant::now(), done);
    }
}

/// Run one batch to completion. Spawned by the entry points; awaited directly
/// by the tests.
///
/// The plan is a page stream: each page is dispatched as it loads, so the first
/// probe starts within a page instead of after the whole feed (resolving every
/// page first cost ~5.8 s of dead air on the 2026-09-17 reference feed), and
/// every link's real half is dispatched by its own chain once that link's fast
/// half has settled — there is no phase barrier and no gate queue on the path.
pub(crate) async fn run_batch(mut params: BatchParams) {
    let source = std::mem::replace(&mut params.plan, PlanSource::Links(Vec::new()));
    let page_size = params.page_size.max(1);
    let mut walk = PlanWalk::new(source, params.db.clone(), page_size);
    let shared = Arc::new(BatchShared::new(params));
    // Publish the handle before the first probe: a batch's record has to exist
    // for as long as the batch can be interrupted, and the shared state
    // (counters + class histograms + meters) is what the quit path renders.
    let _ = shared.batch_slot.set(Arc::clone(&shared));

    // ── Walk and dispatch: the plan is consumed page by page ──────────
    let walk_started = Instant::now();
    let mut walk_error: Option<leas_db::DatabaseError> = None;
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            // Stop at the dispatch boundary: the rest of the plan is never
            // scheduled, so it never writes anything.
            break;
        }
        match walk.next_page().await {
            Ok(Some(links)) => {
                shared
                    .meters
                    .plan_pages_total
                    .store(walk.pages_total(), Ordering::Relaxed);
                shared.dispatch_page(links).await;
                shared
                    .meters
                    .plan_pages_done
                    .store(walk.pages_done(), Ordering::Relaxed);
            }
            Ok(None) => break,
            Err(e) => {
                // The pages already dispatched are probing: keep them and finish
                // normally rather than discarding visible results for a plan
                // error the summary reports.
                walk_error = Some(e);
                break;
            }
        }
    }
    shared.plan_ms.store(
        u32::try_from(walk_started.elapsed().as_millis()).unwrap_or(u32::MAX),
        Ordering::Relaxed,
    );
    tracing::info!(
        target: "tui::ops::ping",
        "{}",
        plan_line(
            shared.plan_len(),
            walk.pages_done(),
            shared.plan_ms.load(Ordering::Relaxed),
        ),
    );
    if let Some(e) = &walk_error {
        tracing::warn!(
            target: "tui::ops::ping",
            "batch: plan walk stopped after {} page(s): {e}",
            walk.pages_done(),
        );
    }
    if shared.plan_len() == 0 && !shared.stop.load(Ordering::Relaxed) {
        // Nothing was planned at all (an empty feed, or a walk that failed on
        // its first page): no work exists to flush or sweep, so the batch ends
        // with the terminal event alone. A stop before the first page is NOT
        // this case — the feed may hold thousands of links the run never
        // touched, and those are exactly the rows `finish_batch`'s error sweep
        // exists for.
        tracing::warn!(target: "tui::ops::ping", "batch: no links to test");
        let _ = shared.tx.try_send(CoreEvent::BatchEnded);
        return;
    }
    if shared.real_phase {
        warn_if_real_phase_is_slow(shared.real_concurrency, shared.plan_len() as usize);
    }

    // Wait for every chain and deferral retry to settle, then join them: the
    // counters say when work is settled, the join makes the batch's end a hard
    // boundary (a chain also runs between its fast settle and its real
    // dispatch, which no counter covers).
    loop {
        // Register the waiter BEFORE reading the counters: `notify_waiters`
        // only wakes already-registered waiters, so a task that settles in
        // between would otherwise be a lost wakeup and this loop would park
        // forever.
        let settled = shared.settled.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        if shared.pending_fast.load(Ordering::Relaxed) == 0
            && shared.pending_real.load(Ordering::Relaxed) == 0
            && shared.pending_deferred.load(Ordering::Relaxed) == 0
        {
            break;
        }
        settled.await;
    }
    let tasks = std::mem::take(&mut *shared.tasks.lock());
    for task in tasks {
        let _ = task.await;
    }
    finish_batch(&shared).await;
}

/// The plan as a page stream.
///
/// A batch dispatches each page as it loads, so the first probe starts within a
/// page of the walk instead of after the whole feed: the loader used to resolve
/// every page first, and on the 2026-09-17 reference feed (18,334 endpoints,
/// ~92 pages × the measured 63 ms per page) that was ~5.8 s of dead air before
/// the first socket dial. It also holds no `Vec<PlanLink>` for the whole feed —
/// only the per-link maps the probes read.
enum PlanWalk {
    /// An explicit plan (the selected-endpoint entry points and the tests): one
    /// page.
    Links(std::vec::IntoIter<Vec<PlanLink>>),
    /// The whole feed, walked page by page through the tab's own query.
    Feed {
        db: Arc<Database>,
        /// The plan scope: which endpoints the walk visits.
        scope: PlanScope,
        /// The frozen endpoint ids of a SCOPED walk, read once before any probe
        /// runs — the scope predicate is derived state this batch mutates, so
        /// offset paging over the live predicate would skip rows. `None` while
        /// unscoped (streams one page at a time) and until a scoped walk's first
        /// page.
        frozen: Option<Vec<EndpointId>>,
        page_size: usize,
        offset: usize,
        pages_done: u32,
        pages_total: u32,
        exhausted: bool,
    },
}

impl PlanWalk {
    fn new(source: PlanSource, db: Arc<Database>, page_size: usize) -> Self {
        match source {
            PlanSource::Links(links) => Self::Links(vec![links].into_iter()),
            PlanSource::Feed(scope) => Self::Feed {
                db,
                scope,
                frozen: None,
                page_size,
                offset: 0,
                pages_done: 0,
                pages_total: 0,
                exhausted: false,
            },
        }
    }

    const fn pages_done(&self) -> u32 {
        match self {
            Self::Links(_) => 1,
            Self::Feed { pages_done, .. } => *pages_done,
        }
    }

    const fn pages_total(&self) -> u32 {
        match self {
            Self::Links(_) => 1,
            Self::Feed { pages_total, .. } => *pages_total,
        }
    }

    /// The next page of links, or `None` when the walk is exhausted. The first
    /// feed page also carries the feed-wide endpoint count (one `COUNT` for the
    /// whole walk, not one per page).
    async fn next_page(&mut self) -> Result<Option<Vec<PlanLink>>, leas_db::DatabaseError> {
        match self {
            Self::Links(iter) => Ok(iter.next()),
            Self::Feed {
                db,
                scope,
                page_size,
                offset,
                pages_done,
                pages_total,
                exhausted,
                frozen,
            } => {
                if *exhausted {
                    return Ok(None);
                }
                // The walk freezes its endpoint set BEFORE the first probe is
                // dispatched, for EVERY scope including `All`. The scope
                // predicate reads the endpoint's `rank_bin`, which this very
                // batch changes as its results land, so an offset-paged walk
                // over a mutating set silently SKIPS every endpoint that leaves
                // the scope: a `Failed` run moves its own endpoints to tier 0 as
                // they succeed, the filtered set shrinks, and the next page's
                // OFFSET lands past rows it never visited.
                //
                // `All` used to be exempt because its `PageSort::Id` order was
                // result-independent — ids never move. Ordering it by the
                // decision-16 law (spec
                // `2026-10-01-static-config-weight-design`) gives that up
                // DELIBERATELY: the order is now the weight/metric ranking
                // this batch itself rewrites, so the same skip applies. The
                // price is one full-feed id read before the first probe instead
                // of a page-at-a-time stream.
                if frozen.is_none() {
                    let request = PageRequest {
                        view: PurgatoryView::All,
                        active_threshold: 0,
                        scope: *scope,
                        search: None,
                        group_id: None,
                        sort: FEED_SORT,
                        ascending: true,
                        offset: 0,
                        limit: usize::MAX,
                    };
                    let page = db.profiles_page(&request).await?;
                    let pages = page
                        .total
                        .div_ceil(u64::try_from(*page_size).unwrap_or(u64::MAX));
                    *pages_total = u32::try_from(pages).unwrap_or(u32::MAX);
                    *frozen = Some(page.ids);
                }
                let all = frozen.as_ref().expect("frozen just above");
                if *offset >= all.len() {
                    *exhausted = true;
                    return Ok(None);
                }
                let end = (*offset + *page_size).min(all.len());
                let ids: Vec<EndpointId> = all[*offset..end].to_vec();
                *offset = end;
                *pages_done += 1;
                // Purged links are skipped by a feed-wide sweep: the real half
                // is the long pole, and re-proving a link the classifier has
                // already judged is the one thing the purge exists to stop.
                // The selected-endpoint entry points read the loaded page
                // instead, so a real test on a Purgatory row still probes it
                // (spec §8, D3).
                let rows = db.load_page_projection(&ids, false).await?;
                Ok(Some(rows.iter().flat_map(plan_row_links).collect()))
            }
        }
    }
}

/// Attempts for the batch-end flush. Contention with a concurrent import is
/// transient (the import commits in 500-link chunks) and the driver already
/// waits `busy_timeout` (5 s) inside each attempt — so this is a short bounded
/// retry, not a stacked backoff. A dedicated failure-injection test is not
/// written: every injected failure costs the driver's full busy wait (measured
/// in the link writer's lock test), and the retry only decides how many times the
/// same single call is repeated.
const FINAL_FLUSH_ATTEMPTS: u32 = 3;

/// Signal the batch's end. Runs the error-TTL sweep first (design §6.4): batch
/// completion is a natural "errors are fresh now" boundary, so persisted failure
/// markers older than the configured TTL are cleared before the terminal event
/// lands. Links the batch did not touch (dedup-retired siblings, queue-full/stop
/// skips) are exactly the ones whose stale markers this clears.
/// Whether the batch end runs `wal_checkpoint(PASSIVE)`.
///
/// It used to be `!concurrent_writes`, because under MVCC the engine rejected
/// the statement outright with `PASSIVE checkpoint requires
/// experimental_mvcc_passive_checkpoint`. `file_driver` now sets that flag with
/// the MVCC opt-in, so it succeeds under both journal modes (and MVCC's own
/// auto-checkpoints switch from blocking `Truncate` to `Passive`). Kept as a
/// named predicate so the reason is visible and a future engine change has one
/// place to point at.
const fn wal_checkpoint_enabled(_concurrent_writes: bool) -> bool {
    true
}

async fn finish_batch(shared: &BatchShared) {
    // Make the batch durable before the sweeps look at the rows: the staged
    // result/task writes land in one transaction here instead of one commit
    // per result on the UI task.
    //
    // Retried: this is the batch's durability point, and the background flush
    // loop may not outlive it. A failed attempt re-stages the whole unwritten
    // remainder (see `WriteBehind::flush`), so a later attempt writes it all.
    let mut flush_error = None;
    for attempt in 0..FINAL_FLUSH_ATTEMPTS {
        match shared.writer.flush().await {
            Ok(_) => {
                flush_error = None;
                break;
            }
            Err(e) => {
                flush_error = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50 << attempt.min(3))).await;
            }
        }
    }
    if let Some(e) = flush_error {
        tracing::warn!(
            target: "tui::ops::ping",
            "batch flush failed after {FINAL_FLUSH_ATTEMPTS} attempts: {e}"
        );
    }
    // `wal_checkpoint(PASSIVE)` is accepted in both journal modes now: it used
    // to be REJECTED under MVCC ("PASSIVE checkpoint requires
    // experimental_mvcc_passive_checkpoint"), so the batch simply skipped it.
    // The log is not left to grow by that — the engine auto-checkpoints MVCC on
    // the commit path at ~4.12 MB — but without the flag those auto-checkpoints
    // take the blocking `Truncate` mode, which `file_driver` now avoids.
    if wal_checkpoint_enabled(shared.db.uses_concurrent_writes())
        && let Ok(Ok(mut conn)) =
            tokio::time::timeout(std::time::Duration::from_secs(2), shared.db.connection()).await
    {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            // PASSIVE, not TRUNCATE: TRUNCATE blocks until every reader has
            // released its WAL read mark, and the pool keeps connections
            // alive — a busy checkpoint would stall the batch instead of
            // merely leaving the WAL larger.
            toasty::sql::query("PRAGMA wal_checkpoint(PASSIVE)").exec(&mut conn),
        )
        .await;
    }
    crate::ops::profiles::clear_expired_errors(&shared.db, shared.error_ttl_hours).await;
    // One line per batch: the per-result lines are `debug`, so this is the
    // record a reader (and the next investigation) works from.
    tracing::info!(target: "tui::ops::ping", "{}", summary_line(shared));
    let _ = shared.tx.try_send(CoreEvent::BatchEnded);
}

/// The plan's own record: the pages and links the walk produced and how long it
/// took. Emitted once, after the walk (a stop or a page error ends it early, and
/// the line then reports the partial plan — which is why the counts are here and
/// not derived from the feed).
fn plan_line(links: u32, pages: u32, plan_ms: u32) -> String {
    format!("batch: planned {links} link(s) over {pages} page(s) in {plan_ms} ms")
}

/// The batch's single log record: the planned links and pages, the per-level
/// outcomes with their class histograms, the two overlapping level spans (the
/// pipeline runs both levels at once, so they are not phases) and the writer's
/// own durability answer (`staged-left` is non-zero only if a flush never
/// succeeded).
pub(crate) fn summary_line(shared: &BatchShared) -> String {
    let counters = &shared.counters;
    let load = |counter: &AtomicU32| counter.load(Ordering::Relaxed);
    format!(
        "batch summary: links={} plan={} ms untestable={} queue-full={} deferred={} | fast ok={} hard-fail={} soft-fail={} {} ({}..{} ms) | real ok={} failed={} {} skipped-unreachable={} ({}..{} ms) | levels overlap | wall={} ms stopped={} flushes={} staged-left={}",
        shared.plan_len(),
        shared.plan_ms.load(Ordering::Relaxed),
        load(&counters.untestable),
        load(&counters.queue_full),
        load(&counters.deferred),
        load(&counters.fast_ok),
        load(&counters.fast_hard_failed),
        load(&counters.fast_soft_failed),
        class_histogram(&counters.fast_fail),
        shared.fast_started_ms.load(Ordering::Relaxed),
        shared.fast_ended_ms.load(Ordering::Relaxed),
        load(&counters.real_ok),
        load(&counters.real_failed),
        class_histogram(&counters.real_fail),
        load(&counters.unreachable),
        shared.real_started_ms.load(Ordering::Relaxed),
        shared.real_ended_ms.load(Ordering::Relaxed),
        shared.started.elapsed().as_millis(),
        shared.stop.load(Ordering::Relaxed),
        shared.writer.flush_count(),
        shared.writer.staged_len(),
    )
}

/// Count one failure into its class bucket.
fn bump_class(map: &Mutex<BTreeMap<ProbeClass, u32>>, class: ProbeClass) {
    *map.lock().entry(class).or_default() += 1;
}

/// Render a failure histogram as `[timeout=8924 dns=4119 …]`, in class order.
/// Empty when nothing failed — the reason `hard-fail=` / `failed=` alone is not
/// enough: a run's dominant class is what a fix is aimed at.
fn class_histogram(map: &Mutex<BTreeMap<ProbeClass, u32>>) -> String {
    // Snapshot first: the guard is released before any string work, so a
    // probe task can never block on the summary's formatting.
    let counts: Vec<(ProbeClass, u32)> = map.lock().iter().map(|(c, n)| (*c, *n)).collect();
    if counts.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (class, count) in counts {
        if out.len() > 1 {
            out.push(' ');
        }
        out.push_str(class.label());
        out.push('=');
        out.push_str(&count.to_string());
    }
    out.push(']');
    out
}

/// The record of a batch that never reached its own summary — the quit path
/// renders this after flushing, because the runtime drop cancels the batch task
/// (`finish_batch`'s line is how the 2026-09-16 run ended with 31k persisted
/// results and nothing in the log describing the run).
///
/// This is the SAME summary a completed run writes, so the per-class
/// histograms survive an interruption, plus the two counts `finish_batch` does
/// not need: what the levels had settled, and what was still in flight (task
/// slots plus the deferral retries, which hold no gate entry).
pub(crate) fn interrupted_summary_line(shared: &BatchShared) -> String {
    let settled = shared.meters.main.done.load(Ordering::Relaxed);
    let in_flight = shared.pending_fast.load(Ordering::Relaxed)
        + shared.pending_real.load(Ordering::Relaxed)
        + shared.pending_deferred.load(Ordering::Relaxed);
    format!(
        "batch interrupted at quit: {} | settled={settled} in-flight={in_flight}",
        summary_line(shared),
    )
}

/// Warn once per real-phase batch whose concurrency is below
/// [`REAL_CONCURRENCY_WARN_BELOW`]: a real probe holds its slot for a dial plus
/// (on failure) the whole timeout, so the phase's rate is roughly
/// `concurrency / timeout` — the measured run held a 34,562-link plan at 2.45
/// results/s with a saved override of 5 (default [`REAL_CONCURRENCY_DEFAULT`]),
/// which is ~4 h. The value is the user's to set; this only says what it costs.
fn warn_if_real_phase_is_slow(real_concurrency: usize, plan_len: usize) {
    if real_concurrency >= REAL_CONCURRENCY_WARN_BELOW as usize {
        return;
    }
    tracing::warn!(
        target: "tui::ops::ping",
        "real ping concurrency {real_concurrency} is below {REAL_CONCURRENCY_WARN_BELOW} (code default {REAL_CONCURRENCY_DEFAULT}): a real probe holds its slot for a dial plus the full timeout, so the real phase is throughput-bound (~2.45 results/s at 5 on the 2026-09-16 run) and this {plan_len}-link plan will not finish in a session — raise speed_test.real_ping_concurrency"
    );
}

/// One startup line naming the values a batch's behaviour depends on: the
/// analysis of the 2026-09-15 run had to read them out of `config.json`, and
/// the loaded page size is what the plan is bounded by.
pub fn log_startup_envelope(state: &AppState) {
    let speed = &state.config.speed_test;
    tracing::info!(
        target: "tui::ops::ping",
        "startup: version={} page={} rows tcp-timeout={:?} real-timeout={:?} real-retries={} real-concurrency={} dedup-endpoints={} error-ttl={:?}",
        env!("CARGO_PKG_VERSION"),
        state.endpoints.len(),
        speed.tcp_timeout_secs,
        speed.real_ping_timeout_secs,
        speed.real_ping_retries,
        speed.real_ping_concurrency,
        !speed.real_ping_test_all_protocols,
        speed.error_ttl_hours,
    );
}

/// Drive one link's chain: its fast half, then the real half that half's settle
/// dispatches (real-phase batches). The gate keeps a link's halves from
/// overlapping; this chain, not a queue, hands the link from one to the other.
///
/// A stop at a dispatch boundary retires the task silently — no result event, no
/// error marker.
async fn run_task_chain(
    shared: Arc<BatchShared>,
    link: ProfileStats,
    mut id: u16,
    mut kind: TaskKind,
) {
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            shared.sched.complete(&link, id, kind).await;
            shared.note_settled(kind);
            // The real half of a stopped link is never dispatched, so it is never
            // counted: `after_fast_settle` owns the accounting, and a link that
            // never reached it has nothing outstanding.
            return;
        }
        match kind {
            TaskKind::FastPing => {
                // The fast half takes NO permit of its own (spec D14): it is a
                // TCP handshake, not a native handshake, and the one limit
                // that matters — the one that bounds native handshakes — is
                // `real_ping_concurrency`.
                shared.mark_started(&shared.fast_started_ms);
                // The MERGED pipeline (spec D1): in a real-phase batch there is
                // NO separate TCP ping. The probe's own TRANSPORT stage
                // measures the same thing the fast probe measured, and the
                // probe produces BOTH facts in one pass — so a TCP ping first
                // would open the same connection twice for the same answer.
                //
                // So the real-phase chain goes STRAIGHT to the probe: the
                // probe's transport stage IS the fast measurement, and it
                // rides along in the probe's result (spec D12).
                //
                // The fast-only batch ("Fast Test") keeps the TCP probe: it
                // never builds a tunnel, so the transport span is all it can
                // produce.
                if shared.real_phase {
                    shared.sched.complete(&link, id, TaskKind::FastPing).await;
                    shared.note_settled(TaskKind::FastPing);
                    // The untestable marker comes first and applies to BOTH
                    // batch kinds: a row the engine cannot serve is never a
                    // real candidate, and dropping the marker would leave a
                    // genuine-looking failure behind that
                    // `remove_failed_servers` would delete.
                    let key = (link.protocol_id, link.endpoint_id);
                    if let Some(reason) = shared.untestable.get(&key).map(|r| r.value().clone()) {
                        shared.counters.untestable.fetch_add(1, Ordering::Relaxed);
                        shared.emit_untestable_marker(&link, &reason);
                    } else {
                        // The link is a real candidate: the probe produces BOTH
                        // facts — the transport span (the Fast column) and the
                        // real span (the Real column) — in one pass.
                        //
                        // The denominator was already counted at plan time
                        // (`dispatch_page`), so nothing is added here.
                        if !shared.dispatch_real_probe(link.clone(), true).await {
                            shared.spawn_defer_retry(link.clone(), Half::Real);
                        }
                    }
                    // The chain FALLS THROUGH to the promotion loop below —
                    // NOT a `return`. `sched.complete` promoted the link's next
                    // task, and the gate's promoted id is what FIRES it;
                    // returning early would leave that task queued forever, its
                    // `pending_real` never draining, and the batch waiting out
                    // the whole deferral budget before it could end.
                } else {
                    let outcome = shared.fast_probe(&link).await;
                    shared.emit_result(&link, TestType::TcpPing, &outcome);
                    shared.sched.complete(&link, id, TaskKind::FastPing).await;
                    shared.note_settled(TaskKind::FastPing);
                    // The fast result is staged: the link's untestable marker
                    // (for either batch kind) follows here.
                    shared.after_fast_settle(&link).await;
                }
            }
            TaskKind::RealPing => {
                // Defensive: the batch never queues, so this arm is reached only
                // when another chain held this link's gate and promoted our id.
                shared.mark_started(&shared.real_started_ms);
                shared.run_real_task(&link, id).await;
            }
            _ => return, // SpeedTest/UdpTest tasks are not part of the batch
        }
        // Fire the promoted task, if any. The gate owns task state, so ask it for
        // the link's new current id (an id the registry does not know cannot come
        // back: the gate and the registry advance together).
        let Some(next_id) = shared.sched.task_of(&link) else {
            return;
        };
        if next_id == id {
            // The gate did not advance (stale completion) — do not spin.
            return;
        }
        let Some(next_kind) = shared.sched.kind_of(next_id) else {
            return;
        };
        id = next_id;
        kind = next_kind;
    }
}

impl BatchShared {
    /// True when the endpoint's PERSISTED resolution attempt is inside the TTL.
    ///
    /// The handler's gate reads the SESSION's `endpoint_info`, which is seeded
    /// for the loaded page only — so without this every off-page DNS endpoint is
    /// re-resolved on every run. That wastes lookups and, worse, a transient
    /// failure anywhere in the fan-out calls `scheduler.mark_dns_failure` and
    /// DNS-defers a healthy endpoint inside the very batch that asked for it.
    ///
    /// A DNS host whose lookups never produced addresses carries no persisted
    /// attempt (a failed lookup does not clear the address set), so it stays a
    /// candidate — which is exactly the case this feature exists for.
    fn dns_resolution_is_fresh(&self, endpoint: &Endpoint) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        endpoint
            .resolved_at
            .is_some_and(|attempted| now.saturating_sub(attempted) < self.dns_cache_ttl_secs)
    }

    /// Schedule one page's links. The maps the probes read are filled here, so a
    /// link's own halves find their config and endpoint without a second pass
    /// over the whole plan.
    ///
    /// The GROUP-ENTRY barrier (spec D15/T3.1) lives here. The plan's links
    /// are CONTIGUOUS per endpoint (the walk sorts endpoints and each
    /// endpoint's links come back together — `plan_row_links` → `row.links`),
    /// so the group is read from the page in order: the endpoint's FIRST
    /// protocol is dispatched and its SIBLINGS are deferred to the back of the
    /// queue. When the first protocol's verdict lands, the siblings are
    /// either dropped (the endpoint succeeded) or released.
    ///
    /// The walk's ORDER is unchanged (`PageSort::Test`): the group is
    /// contiguous in the plan the walk already produces, so no new order and no
    /// new query is introduced.
    async fn dispatch_page(self: &Arc<Self>, links: Vec<PlanLink>) {
        // The group's siblings, held back until the first protocol's verdict
        // lands. Keyed by endpoint id: the group is the endpoint's links.
        let mut deferred_siblings: HashMap<i64, Vec<ProfileStats>> = HashMap::new();
        // The endpoint ids whose first protocol has already been dispatched in
        // this page. The group is contiguous, so the SECOND link of an
        // endpoint is a sibling, not a new group.
        let mut group_seen: HashSet<i64> = HashSet::new();
        // One resolution request per DNS endpoint for the whole batch. The
        // handler's TTL gate makes a completed repeat cheap, but a request
        // waiting on the resolver semaphore is invisible to that gate.
        for plan in links {
            let key = (plan.link.protocol_id, plan.link.endpoint_id);
            self.fast_config
                .insert(key, plan.protocol.proto_kind.to_i32());
            // One entry per endpoint, not per link: every link of an endpoint
            // shares the plan's `Arc`, and the map only needs the first.
            self.endpoints
                .entry(plan.endpoint.id)
                .or_insert_with(|| Arc::clone(&plan.endpoint));
            self.addrs
                .entry(plan.endpoint.id)
                .or_insert_with(|| plan.addresses.clone());
            // A feed-wide plan reaches endpoints the UI never loads, so the
            // batch asks for their resolution itself: resolving "the endpoint by
            // id" in the result handler only ever sees the loaded page, which is
            // how a full run left every off-page DNS host `[name]` while it
            // persisted their exit IPs. Best-effort like every other batch
            // event: a full channel drops the request, and the next batch (or a
            // connect) asks again.
            let endpoint_id = plan.endpoint.id.get();
            // Claim the endpoint for this batch and hand the request to the
            // channel, both under one lock so two pages cannot ask twice. The
            // marker is written after the guard is released — it is a
            // synchronous map insert, and holding a std mutex across it is what
            // the early-drop lint is about.
            let sent = {
                let mut requested = self.resolve_requested.lock();
                if plan.endpoint.is_dns()
                    && !self.dns_resolution_is_fresh(&plan.endpoint)
                    && !requested.contains(&endpoint_id)
                {
                    let request = CoreEvent::DnsResolveRequest {
                        endpoint_id,
                        host: plan.endpoint.dns_name(),
                        host_type: leas_db::models::HostType::Dns,
                        sni: crate::ops::enrich::extract_sni(
                            &plan.protocol,
                            &plan.endpoint.dns_name(),
                        ),
                    };
                    // A full channel drops it; the next batch (or a connect)
                    // asks again, so only a SENT one is recorded.
                    if self.tx.try_send(request).is_ok() {
                        requested.insert(endpoint_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if sent {
                // Mark the lookup in flight HERE, not in the handler: the
                // request travels a bounded channel to the UI task and is
                // handled on a later tick, so a link scheduled in this same
                // iteration would otherwise start before the resolver was even
                // asked — and the gate could never defer it, because the
                // failure report that would justify the deferral arrives 8s
                // later still. That is why the 2026-09-27 run reported
                // `deferred=0` against 196 DNS failures. The handler re-marks
                // on the non-batch paths; an insert is idempotent.
                self.sched
                    .begin_dns_lookup(leas_db::models::EndpointId::new(endpoint_id));
            }
            // The kind-level testability gate: it needs only the in-memory
            // `proto_kind`, so it is decided here — the one place every batch
            // (production and test) passes through. The config-aware half runs
            // inside the real probe, the only place a loaded config exists.
            if !capability::kind_supported(plan.protocol.proto_kind) {
                self.untestable.insert(
                    key,
                    untestable_marker_text(capability::KIND_UNSUPPORTED_REASON),
                );
            }
            // The ONE level's denominator: every PLANNED link is counted here,
            // once. The real-phase chain below adds nothing — it would
            // double-count every link.
            self.meters.main.total.fetch_add(1, Ordering::Relaxed);
            let link = plan.link;
            // The GROUP-ENTRY gate: the endpoint's first protocol is probed
            // immediately; its siblings wait for that protocol's verdict.
            //
            // The walk's order is unchanged — the group's links are CONTIGUOUS
            // in the plan, so the second link of an endpoint is the sibling of
            // the first, not a new group.
            //
            // The gate is the DEDUPLICATING real phase's: a fast-only batch
            // has no verdict to wait for, and `dedup_endpoints == false` is
            // the explicit "test every protocol of the endpoint" setting
            // (`real_ping_test_all_protocols`) — its siblings have their own
            // exit IPs to find, so they are not held back.
            if !self.real_phase
                || !self.dedup_endpoints
                || group_seen.insert(link.endpoint_id.get())
            {
                if !self.dispatch_fast_link(link.clone()).await {
                    self.spawn_defer_retry(link, Half::Fast);
                }
            } else {
                // A SIBLING: held back until the group's first protocol's
                // verdict lands (the endpoint succeeded → the whole group is
                // dropped; the endpoint did not succeed → the siblings are
                // released and probed).
                deferred_siblings
                    .entry(link.endpoint_id.get())
                    .or_default()
                    .push(link);
            }
        }
        // The group's siblings are held in the PAGE, but the group's verdict
        // may land after the page is dispatched — so the release is the
        // settle path's job, and the page's map is handed over to it.
        self.hold_siblings(deferred_siblings);
    }

    /// Hold a page's deferred siblings until their group's verdict lands.
    fn hold_siblings(&self, siblings: HashMap<i64, Vec<ProfileStats>>) {
        if siblings.is_empty() {
            return;
        }
        let mut held = self.deferred_siblings.lock();
        for (endpoint_id, links) in siblings {
            held.entry(endpoint_id).or_default().extend(links);
        }
    }

    /// Schedule one link's fast half.
    ///
    /// Returns `false` only for `DnsDeferred`, and the caller owns the retry —
    /// one retry task per deferred half, looping inside itself. `Queued` is the
    /// defensive case (another chain holds this link's gate and its `complete`
    /// promotes ours): the batch itself never queues, because a queued real half
    /// would depend on `task_queue_limit` and a `DnsDeferred` link has no gate
    /// entry to queue behind (`schedule` answers before the lock).
    async fn dispatch_fast_link(self: &Arc<Self>, link: ProfileStats) -> bool {
        match self.sched.schedule(&link, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => {
                self.pending_fast.fetch_add(1, Ordering::Relaxed);
                let shared = Arc::clone(self);
                self.spawn_tracked(async move {
                    run_task_chain(shared, link, id, TaskKind::FastPing).await;
                });
                true
            }
            ScheduleOutcome::Queued(_) => {
                self.pending_fast.fetch_add(1, Ordering::Relaxed);
                true
            }
            ScheduleOutcome::DnsDeferred => {
                self.counters.deferred.fetch_add(1, Ordering::Relaxed);
                false
            }
            ScheduleOutcome::QueueFull => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                // Per-link: a feed-wide batch would flood the log. The summary
                // carries the count.
                tracing::debug!(target: "tui::ops::ping", "batch: link skipped, queue full");
                true
            }
        }
    }

    /// Everything a link owes once its fast result is staged.
    ///
    /// The FAST-ONLY path: a real-phase batch goes straight to the probe (the
    /// merged pipeline, spec D1), so the fast half's gates — the untestable
    /// marker and the hard-failure retirement — are re-homed to the probe's
    /// own path (`run_task_chain`'s real-phase arm and `real_probe`).
    ///
    /// The untestable marker comes first and applies to BOTH batch kinds: the
    /// single pass this replaces ran before the fast-only early return, so a
    /// fast-only batch marks such rows today — dropping the marker would leave a
    /// genuine-looking failure behind and `remove_failed_servers` would delete
    /// the row (the marker outranks a measurement in the Real cell). A marked
    /// link is never a real candidate.
    async fn after_fast_settle(self: &Arc<Self>, link: &ProfileStats) {
        let key = (link.protocol_id, link.endpoint_id);
        let untestable = self.untestable.get(&key).map(|r| r.value().clone());
        if let Some(reason) = untestable {
            self.counters.untestable.fetch_add(1, Ordering::Relaxed);
            self.emit_untestable_marker(link, &reason);
            return;
        }
        // The fast level already proved this link's proxy unreachable (refused,
        // no route, unresolvable, dial timeout): the real probe would only spend
        // its whole timeout re-learning that. The row keeps its `[fast]` marker,
        // which is the honest statement about it.
        if self.hard_fast.lock().contains(&key) {
            // …unless the fast level CANNOT measure this row. A `mode=quic`
            // plugin row is served over QUIC/UDP and the fast level is a TCP
            // handshake, so its hard failure is evidence about the fast level,
            // not about the server: retiring here left every quic row
            // permanently `[fast]`-failed and untested no matter what the server
            // was. The marker goes with the verdict — a TCP timeout is not a
            // statement about a QUIC server.
            //
            // The check is HERE, on the rare hard-failure arm, and reads the
            // batch's per-`ProtocolId` config cache. It is deliberately NOT the
            // plan-time gate: that would cost a config load per planned link,
            // including for the rows this exemption will never apply to.
            if self.is_quic_plugin_link(link).await {
                self.retract_fast_marker(link);
            } else {
                self.counters.unreachable.fetch_add(1, Ordering::Relaxed);
                // The retirement stands in for the real probe it prevented — a
                // hard-fast failure is evidence the link is unreachable NOW
                // (spec §7.2). Gated on `real_phase`: a fast-ONLY pass must not
                // fill rings with failures no real probe can offset.
                //
                // It goes in THIS arm, with the verdict — never on
                // `hard_fast.contains(key)`: the quic-plugin link above is
                // reachable and does get real-probed, so a sample there would
                // demote a working link.
                if self.real_phase {
                    self.sample_stability(link, false);
                }
                return;
            }
        }
        // Above the hard-failure block on purpose, and reachable in a fast-ONLY
        // batch ("Fast Test", `real_phase == false`) as well as the merged
        // one: the retraction is a statement about the FAST probe's verdict, not
        // about the real level, so it must not be gated on whether a real level
        // exists. Returning above it left every quic row carrying the TCP-derived
        // `[fast]` marker in a fast-only run — the §8.1 symptom, unfixed.
        if !self.real_phase {
            return;
        }
        // A candidate is known: every path out of `dispatch_real_probe` counts
        // it exactly once into `main.done` (probe, sibling retire, stop retire,
        // queue-full). The denominator was counted at plan time.
        if !self.dispatch_real_probe(link.clone(), true).await {
            self.spawn_defer_retry(link.clone(), Half::Real);
        }
    }

    /// Dispatch a link's real half.
    ///
    /// The permit is taken BEFORE the sibling check on purpose: for an endpoint
    /// whose links settle together, the probes `dedup_endpoints` saves are the
    /// ones still waiting for capacity when a sibling's real ping succeeded.
    ///
    /// `counted` says this half's candidate is already in `real.total`; a
    /// deferral retry passes `false` so a retried half is never counted twice.
    /// Returns `false` only for `DnsDeferred` (the caller re-enters later).
    async fn dispatch_real_probe(self: &Arc<Self>, link: ProfileStats, counted: bool) -> bool {
        let Ok(permit) = Arc::clone(&self.real_sem).acquire_owned().await else {
            return true;
        };
        if self.stop.load(Ordering::Relaxed) {
            if counted {
                self.note_real_done();
            }
            return true;
        }
        if self.dedup_endpoints
            && self
                .completed_endpoints
                .lock()
                .contains(&link.endpoint_id.get())
        {
            // A sibling already succeeded: retire this half without a probe and
            // without a result event, so no marker is written.
            if counted {
                self.note_real_done();
            }
            return true;
        }
        match self.sched.schedule(&link, TaskKind::RealPing).await {
            ScheduleOutcome::Started(id) => {
                self.pending_real.fetch_add(1, Ordering::Relaxed);
                self.mark_started(&self.real_started_ms);
                self.run_real_task(&link, id).await;

                drop(permit);
                true
            }
            ScheduleOutcome::Queued(_) => {
                // Promoted by the gate holder's completion (defensive).
                self.pending_real.fetch_add(1, Ordering::Relaxed);
                true
            }
            ScheduleOutcome::DnsDeferred => {
                self.counters.deferred.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                false
            }
            ScheduleOutcome::QueueFull => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                if counted {
                    self.note_real_done();
                }
                true
            }
        }
    }

    /// One real probe, from schedule to settle.
    async fn run_real_task(self: &Arc<Self>, link: &ProfileStats, id: u16) {
        let outcome = self.real_probe(link).await;
        let succeeded = matches!(outcome, ProbeOutcome::Ok { .. });
        // The TRANSPORT-stage failure IS the merged pipeline's retirement rule
        // (spec D1's "not measurable" outcome): the transport did not come up,
        // so the probe cannot pass where the dial did not. The row keeps its
        // transport marker, and the endpoint's other links are retired with
        // it — the same rule the fast half's hard failure used to apply.
        //
        // The FLAG decides it — the engine's own stage, never the class: the
        // stage-1 deadline and the stage-2+ deadline share the class
        // `Timeout`, and a class test would retire a working server whose
        // protocol stage merely hung.
        if let ProbeOutcome::Failed {
            transport_failed: true,
            ..
        } = &outcome
        {
            self.counters.unreachable.fetch_add(1, Ordering::Relaxed);
            // The retirement stands in for the probe it prevented — a
            // transport failure is evidence the link is unreachable NOW
            // (spec §7.2).
            self.sample_stability(link, false);
        }
        // A successful real ping records the endpoint so the sibling-dedup pass
        // skips its remaining links.
        if self.dedup_endpoints && succeeded {
            self.completed_endpoints
                .lock()
                .insert(link.endpoint_id.get());
        }
        self.emit_result(link, TestType::RealPing, &outcome);
        self.sched.complete(link, id, TaskKind::RealPing).await;
        self.note_settled(TaskKind::RealPing);
        self.note_real_done();
        // The GROUP-ENTRY barrier's release: this link was the group's FIRST
        // protocol, so its verdict decides the group's siblings.
        //
        // The endpoint SUCCEEDED → the whole group is dropped (the siblings
        // are never probed, and they write no marker, no delay and no exit
        // IP). The endpoint did NOT succeed → the siblings are released and
        // probed; there is NO second barrier check, so an endpoint whose first
        // config failed still gets its other configs measured.
        //
        // The release is best-effort and never cancels: a sibling already in
        // flight completes and records its full result — the endpoint's
        // success does not suppress a sibling's measurement, because the
        // sibling's config is a DIFFERENT config and may route elsewhere
        // (spec D15).
        self.release_siblings(link.endpoint_id.get(), succeeded);
    }

    /// Release (or drop) a group's held siblings, per the group's verdict.
    ///
    /// The siblings are dispatched through the SAME path the first protocol
    /// took — their fast half first, then their real half — so a released
    /// sibling produces its own full result (its own Fast delay, Auth flag,
    /// Real delay and exit IP), and a sibling that FAILS writes its own
    /// failure marker.
    fn release_siblings(self: &Arc<Self>, endpoint_id: i64, succeeded: bool) {
        let siblings = {
            let mut held = self.deferred_siblings.lock();
            held.remove(&endpoint_id).unwrap_or_default()
        };
        if siblings.is_empty() {
            return;
        }
        if succeeded {
            // The endpoint is known good: the whole group is dropped. The
            // siblings write NOTHING — no probe, no marker, no delay.
            //
            // They were counted into `main.total` at plan time, so they must
            // be counted into `main.done` here: the denominator and the
            // numerator have to meet, or the batch's waiter waits out the
            // whole deferral budget for a link that will never settle.
            self.counters.group_dropped.fetch_add(1, Ordering::Relaxed);
            self.meters
                .main
                .done
                .fetch_add(siblings.len() as u32, Ordering::Relaxed);
            return;
        }
        // The endpoint did not succeed: the siblings are probed. They are
        // dispatched on their own task, so the release does not block the
        // settle path.
        self.counters.group_released.fetch_add(1, Ordering::Relaxed);
        for link in siblings {
            let shared = Arc::clone(self);
            self.spawn_tracked(async move {
                shared.dispatch_fast_link(link).await;
            });
        }
    }

    /// Spawn the one retry task a deferred half gets.
    fn spawn_defer_retry(self: &Arc<Self>, link: ProfileStats, half: Half) {
        self.pending_deferred.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::clone(self);
        self.spawn_tracked(async move {
            shared.defer_retry(link, half).await;
        });
    }

    /// A deferred half sleeps out the window and re-enters its own dispatch.
    ///
    /// It holds no gate entry: `DnsDeferred` is answered before the gate is
    /// touched, so there is nothing to promote — and that is exactly why a
    /// link's two halves cannot separate, since the fast half's re-entry runs
    /// the whole chain and the real half's re-entry is reachable only from a
    /// settled fast half.
    async fn defer_retry(self: &Arc<Self>, link: ProfileStats, half: Half) {
        // How long one half may sit deferred before the batch stops waiting.
        //
        // The loop is meant to outlast a DNS window, not to be the thing that
        // keeps a batch alive: a link is deferred only while its endpoint's
        // lookup is in flight or inside its failure window, and the lookup
        // clears both when it completes. A marker that outlives its lookup is
        // a bug, and unbounded it becomes a HANG — the batch waits for every
        // retry before emitting its terminal event, so this is the last thing
        // between such a leak and a batch that never finishes.
        //
        // Bounded by WAITED TIME, not by attempt count: the poll interval and
        // the window are independent (the tests poll every 50ms against a 2s
        // window), so any fixed attempt count is either too small to outlast a
        //
        // The budget must provably exceed the worst time a lookup can take to
        // REPORT, because `mark_dns_failure` arms its window at report time
        // while this clock starts at the FIRST deferral. The 2026-10-01 run
        // booked 12 halves unprobed exactly that way: `2 × dns_defer_secs` (30 s)
        // against a window armed later still open.
        //
        // Now that the resolver's permit wait is bounded by
        // `DNS_LOOKUP_TIMEOUT` (see `enrich::spawn_dns_resolve_host`), report
        // time is a function of that timeout alone, so
        // `window + timeout + slack` cannot be beaten.
        let budget = Duration::from_secs(self.sched.dns_defer_secs().max(1) as u64)
            .saturating_add(crate::ops::enrich::DNS_LOOKUP_TIMEOUT)
            .saturating_add(Duration::from_secs(1));
        let mut waited = Duration::ZERO;
        // Backoff schedule for the re-entry polls: 250 ms, then doubling, capped
        // at the deferral window. NOT a flat 250 ms — that would be ~60 gate
        // acquisitions per deferred half, and with 1,577 deferred halves ~95k
        // spurious dispatches per batch, which is the very contention the
        // original full-window sleep avoided. Capped at the window so gate
        // pressure stays ~6 acquisitions per half rather than 60.
        let window = Duration::from_secs(self.sched.dns_defer_secs().max(1) as u64);
        // Seeded from `defer_delay` (the test seam) but never above
        // `DEFER_POLL_MIN`: production sets `defer_delay` to the whole window,
        // and sleeping that first is the 15 s floor this task removes.
        let mut backoff = self
            .defer_delay
            .min(DEFER_POLL_MIN)
            .max(Duration::from_millis(1));
        // The budget is a wall clock from the FIRST deferral, but the state it
        // waits on is re-armed at report time — a lookup that starts (or fails)
        // again mid-batch moves that state forward. Without this, a host that
        // fails twice inside one batch is booked unprobed by a clock that
        // started before the second failure existed: the fixed budget formula
        // cannot express that, which is why the stamp is polled here.
        let mut seen_stamp = self.sched.dns_state_stamp(link.endpoint_id);
        loop {
            tokio::time::sleep(backoff).await;
            waited = waited.saturating_add(backoff);
            // Double, capped at the deferral window: past that, polling more
            // often cannot help, and the window is what bounds the wait.
            backoff = (backoff.saturating_mul(2)).min(window);
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            let reached_gate = match half {
                Half::Fast => self.dispatch_fast_link(link.clone()).await,
                Half::Real => self.dispatch_real_probe(link.clone(), false).await,
            };
            if reached_gate {
                break;
            }
            // The deferral state moved: this is a NEW wait, not more of the old
            // one, so the budget starts again rather than being cut off.
            let now_stamp = self.sched.dns_state_stamp(link.endpoint_id);
            if now_stamp != seen_stamp {
                seen_stamp = now_stamp;
                waited = Duration::ZERO;
                continue;
            }
            if waited >= budget {
                // The link was counted in its level's `total` when the page
                // dispatched it, so dropping it here silently would leave the
                // summary's denominator one above its numerators — the exact
                // mismatch the per-level meters exist to prevent. Book it as
                // settled-but-unprobed, under `deferred` (which already means
                // "the gate refused this link").
                // ONE level (spec D14): the half no longer has its own
                // meter, so both halves book the same way.
                let _ = half;
                self.meters.main.done.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "tui::ops::ping",
                    endpoint_id = link.endpoint_id.get(),
                    half = half.as_str(),
                    waited_ms = waited.as_millis() as u64,
                    "batch: a half stayed DNS-deferred past {:?} and was booked unprobed — its lookup never reported in time",
                    budget,
                );
                break;
            }
            tracing::debug!(
                target: "tui::ops::ping",
                "batch: {} half still DNS-deferred",
                half.as_str(),
            );
        }
        if self.pending_deferred.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.settled.notify_waiters();
        }
    }

    /// Fast probe with batch-level dedup: one TCP ping per unique
    /// (address, port); followers await the owner's result and reuse it.
    async fn fast_probe(&self, link: &ProfileStats) -> ProbeOutcome {
        // Clone out of the map: a `DashMap` guard is not `Send`, so it must not
        // be held across the probe's awaits.
        let Some(endpoint) = self
            .endpoints
            .get(&link.endpoint_id)
            .map(|e| Arc::clone(e.value()))
        else {
            return ProbeOutcome::soft_failure("Endpoint not found for fast ping");
        };
        let addrs = self
            .addrs
            .get(&link.endpoint_id)
            .map_or_else(Vec::new, |v| v.value().clone());
        let key = (dial_host(&endpoint, &addrs), endpoint.port);
        let (is_owner, notify) = {
            let mut inner = self.fast_dedup.lock();
            if let Some(outcome) = inner.cache.get(&key) {
                return outcome.clone();
            }
            let pair = match inner.in_flight.entry(key.clone()) {
                Entry::Occupied(existing) => (false, existing.get().clone()),
                Entry::Vacant(slot) => {
                    let n = Arc::new(Notify::new());
                    slot.insert(n.clone());
                    (true, n)
                }
            };
            // Drop the guard before the follower awaits below — a stuck
            // follower must not hold the dedup lock while waiting.
            drop(inner);
            pair
        };
        let timeout = self.fast_timeout;
        let config_type = self
            .fast_config
            .get(&(link.protocol_id, link.endpoint_id))
            .map_or(0, |v| *v.value());
        // The dial host: a DNS name (resolved below) or an IP literal.
        let addr = dial_host(&endpoint, &addrs);
        let port = endpoint.port;
        if is_owner {
            let outcome = self.runner.fast(config_type, &addr, port, timeout).await;
            let mut inner = self.fast_dedup.lock();
            inner.cache.insert(key.clone(), outcome.clone());
            inner.in_flight.remove(&key);
            drop(inner);
            notify.notify_waiters();
            outcome
        } else {
            // Follower: bounded wait — a stuck owner must not wedge the batch.
            tokio::time::timeout(timeout + Duration::from_secs(1), notify.notified())
                .await
                .ok();
            self.fast_dedup
                .lock()
                .cache
                .get(&key)
                .cloned()
                .unwrap_or_else(|| ProbeOutcome::soft_failure("fast ping dedup: owner result lost"))
        }
    }

    /// Real probe for one link: load the protocol row WITH its deferred config
    /// (the builders refuse unloaded configs — mirrors `start_real_ping`)
    /// through the batch's per-`ProtocolId` cache, then run through the engine.
    ///
    /// The MERGED pipeline (spec D1): the probe produces BOTH facts in one
    /// pass — the TRANSPORT stage's span (the Fast column) and the protocol +
    /// probe stage's span (the Real column). They do not overlap, and the
    /// transport span survives a failure (spec D12).
    async fn real_probe(&self, link: &ProfileStats) -> ProbeOutcome {
        let protocol = match self.protocol_config(link.protocol_id).await {
            Ok(loaded) => loaded,
            Err(outcome) => return outcome,
        };
        // Config-level capability gate: kind-level refusals were already retired
        // at plan time, so only a native-capable kind whose CONFIG the engine
        // refuses reaches here. Its marker IS the probe's result — phase 2, so
        // it lands after the fast result and is not cleared by it.
        if let Some(reason) = capability::support_reason(protocol.kind, &protocol.config) {
            return ProbeOutcome::soft_failure(untestable_marker_text(&reason));
        }
        let Some(endpoint) = self
            .endpoints
            .get(&link.endpoint_id)
            .map(|e| Arc::clone(e.value()))
        else {
            return ProbeOutcome::soft_failure("Endpoint not found for real ping");
        };
        let addresses = self
            .addrs
            .get(&link.endpoint_id)
            .map_or_else(Vec::new, |v| v.value().clone());
        self.runner
            .real(
                &endpoint,
                &addresses,
                &protocol.config,
                NativeProbeReq {
                    ping_url: &self.ping_url,
                    ip_provider: self.ip_provider,
                    timeout: self.real_timeout,
                    transport_timeout: self.transport_timeout,
                    retries: self.real_retries,
                },
            )
            .await
    }

    /// The link's protocol row WITH config, loaded from the database at most
    /// once per `ProtocolId` in this batch.
    ///
    /// The load is 67–121 µs (toasty query + JSON decode) and a `Protocol` row
    /// is shared by every endpoint carrying the same config, so the per-link
    /// reload dominated the plan's serial work. Misses are not memoized: a read
    /// error returns this link's failure outcome and the next link tries again.
    async fn protocol_config(&self, id: ProtocolId) -> Result<Arc<LoadedProtocol>, ProbeOutcome> {
        if let Some(hit) = self.protocols.get(&id) {
            return Ok(Arc::clone(hit.value()));
        }
        let row = match load_protocol_with_config(&self.db, id).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                return Err(ProbeOutcome::soft_failure(
                    "Protocol row not found for real ping",
                ));
            }
            Err(e) => {
                return Err(ProbeOutcome::soft_failure(format!(
                    "Failed to load protocol: {e}"
                )));
            }
        };
        let loaded = Arc::new(LoadedProtocol {
            kind: row.proto_kind,
            config: row.config.get().0.clone(),
            // The COLUMN, from the row this struct is built out of — so the
            // purge rule reads the row's own field on every path, never a
            // second source.
            fp: row.security.fp.clone(),
        });
        self.protocols.insert(id, Arc::clone(&loaded));
        Ok(loaded)
    }

    /// Whether this link's protocol is a `mode=quic` SIP003 plugin row.
    ///
    /// A config-load failure answers `false`, i.e. the row keeps the ordinary
    /// retirement: the exemption exists for a row we can positively identify as
    /// QUIC, and a row we could not read is not evidence that it is.
    async fn is_quic_plugin_link(&self, link: &ProfileStats) -> bool {
        let Ok(loaded) = self.protocol_config(link.protocol_id).await else {
            return false;
        };
        let ProtocolConfig::Ss(ss) = &loaded.config else {
            return false;
        };
        ss.plugin
            .as_ref()
            .is_some_and(|p| p.mode == leas_proto::proto_spec::PluginMode::Quic)
    }

    /// Retract the RESULT/PURGE columns a meaningless fast probe staged.
    ///
    /// `stage` REPLACES the pending entry per (link, group), so this wins over
    /// the marker written moments earlier — the retraction is a later fact, not
    /// a merge. Both groups go: a purge verdict derived from a probe that could
    /// not have reached the server is as wrong as its marker.
    fn retract_fast_marker(&self, link: &ProfileStats) {
        // Re-stage the PLAN-TIME SNAPSHOT verbatim, and do NOT blank it.
        //
        // `link` is the batch's snapshot: the fast half only ever wrote into a
        // clone through `stage_result`, so `link.error` is whatever verdict the
        // row carried BEFORE this batch — possibly a valid `[real]` marker from an
        // earlier run, still inside `error_ttl_hours`. Setting `error = None`
        // would destroy that, and if the real half is then retired by a stop or
        // a queue-full the row would be left with no marker at all.
        //
        // `stage` REPLACES the pending entry per (link, group), so re-staging the
        // snapshot is what withdraws the fast half's staged verdict: same shape
        // as every other patch in this batch, which is built from the snapshot.
        let row = link.clone();
        self.writer
            .stage(&row, LinkGroups::RESULT.union(LinkGroups::PURGE));
    }

    /// The purge verdict for one result, or `None`.
    ///
    /// Extracted because it sat verbatim at two sites (`stage_result` and
    /// `emit_result`), so a test at one would not have covered the other and a
    /// future `unwrap_or_default()` on the guard would have flipped the rule to
    /// fail-open with nothing failing.
    ///
    /// **Lazy AND fail-closed.** Lazy: the lookup runs only when there is
    /// evidence — a fast probe's evidence is always `None`, and this is the
    /// write-behind hot path (10.0 ms per 512-patch window). Fail-closed: a
    /// cache MISS returns `None` rather than a verdict, because we cannot tell
    /// whether the shape was approximated, and failing open would let an
    /// approximated probe earn exactly the permanent Purgatory verdict the rule
    /// exists to prevent.
    fn purge_for(
        &self,
        link: &ProfileStats,
        evidence: leas_native::error::FailureEvidence,
    ) -> Option<leas_db::models::PurgeReason> {
        let loaded = self.protocols.get(&link.protocol_id);
        let loaded = loaded.as_ref()?;
        crate::ops::purge::reason_for(evidence, loaded.fp.as_deref())
    }

    /// Append one stability sample for `link` and stage the STAB group.
    ///
    /// The ring is a READ-MODIFY-WRITE over STAGED state (spec
    /// `2026-10-09-stab-bin-design` §7.3): the write-behind drain REMOVES
    /// entries from the pending map, so a snapshot-based append would drop the
    /// sample another producer had already staged for this link. The current
    /// `(mask, len)` therefore come from the pending map when a sample is
    /// staged, falling back to the caller's snapshot only when none is.
    ///
    /// `get` + `push` is not atomic; the scheduler's one-mutex gate serializes
    /// this link's real/fast halves, which is the ordering that matters here.
    fn sample_stability(&self, link: &ProfileStats, ok: bool) {
        let staged = self
            .writer
            .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB))
            .map(|row| (row.link.stab_mask, row.link.stab_len));
        let (mask, len) = staged.unwrap_or((link.stab_mask, link.stab_len));
        let len =
            u8::try_from(len.clamp(0, i64::from(leas_db::endpoint_rank::STAB_WINDOW))).unwrap_or(0);
        let (mask, len) = leas_db::endpoint_rank::append_sample(mask.cast_unsigned(), len, ok);
        let mut row = link.clone();
        row.stab_mask = mask.cast_signed();
        row.stab_len = i64::from(len);
        self.writer.stage(&row, LinkGroups::STAB);
    }

    /// Stage one link's RESULT columns from a probe outcome.
    ///
    /// The batch owns its link snapshots, so persistence does not depend on the
    /// UI's loaded page: the events handler applies results to `state.endpoints`
    /// and stages only what it finds there, and a page reload mid-batch (an
    /// import moves every endpoint's ordering keys) used to drop those results
    /// silently. Staging here is what makes "emitted == persisted" hold.
    fn stage_result(&self, link: &ProfileStats, test_type: TestType, outcome: &ProbeOutcome) {
        let (latency_ms, transport_ms, ip_info, error, purge, marker_kind) = match outcome {
            ProbeOutcome::Ok {
                latency_ms,
                transport_ms,
                ip_info,
            } => (
                *latency_ms,
                *transport_ms,
                ip_info.as_deref(),
                None,
                None,
                None,
            ),
            ProbeOutcome::Failed {
                text,
                evidence,
                transport_ms,
                transport_failed,
                ..
            } => (
                None,
                *transport_ms,
                None,
                Some(text.as_str()),
                evidence.and_then(|ev| self.purge_for(link, ev)),
                // A TRANSPORT-stage failure is the `[fast]` marker even when
                // the probe was a real one (spec D1's "not measurable"
                // outcome): the transport never came up, so the row is not a
                // config verdict.
                transport_failed.then_some(leas_db::models::ProfileErr::Fast),
            ),
        };
        let mut row = link.clone();
        // The fast phase's own measurement, when one ran for this link. It is
        // the SAME class of fact as the probe's transport span (spec D2), so
        // the probe's span — fresher, from the same pass — wins below.
        if let Some(delay) = self
            .fast_latency
            .lock()
            .get(&(link.protocol_id, link.endpoint_id))
        {
            row.latency.fast_delay = Some(*delay);
        }
        // A REAL probe is the one stability sample that ran (spec §7.1). Fast
        // pings prove nothing about the config and never sample; the untestable
        // marker is not a probe at all — the capability gate refused the row —
        // so it must not accrue an attempt (that would sink every native-
        // unsupported link's ratio without a single probe).
        if test_type == TestType::RealPing {
            let refused = matches!(
                outcome,
                ProbeOutcome::Failed { text, .. } if is_untestable_text(text)
            );
            if !refused {
                self.sample_stability(link, matches!(outcome, ProbeOutcome::Ok { .. }));
            }
        }
        // The mapping returns the groups to write: RESULT always, plus PURGE
        // when the verdict moved.
        if let Some(groups) = crate::ops::events::apply_test_result(
            &mut row,
            test_type,
            latency_ms,
            transport_ms,
            None,
            ip_info,
            error,
            purge,
            marker_kind,
        ) {
            self.writer.stage(&row, groups);
        }
    }

    /// Send the `SpeedTestResult` event for a completed probe. The
    /// `TestTypeUpdate` re-arms the events handler's per-protocol dedupe guard
    /// (`testing_profiles`) before the result lands — the real half re-arms for
    /// its own result the same way.
    fn emit_result(&self, link: &ProfileStats, test_type: TestType, outcome: &ProbeOutcome) {
        // Persist first: the event below is a UI notification and may be
        // dropped when the channel is full (`try_send`), the write may not.
        self.stage_result(link, test_type, outcome);
        // The real half reads this: a hard fast failure means the proxy never
        // answered, and a real probe can only spend its timeout finding that out
        // again (253 of 350 real probes did exactly that, 2026-09-15).
        match (test_type, outcome) {
            (
                TestType::TcpPing,
                ProbeOutcome::Ok {
                    latency_ms: Some(delay),
                    ..
                },
            ) => {
                self.counters.fast_ok.fetch_add(1, Ordering::Relaxed);
                self.fast_latency.lock().insert(
                    (link.protocol_id, link.endpoint_id),
                    i32::try_from(*delay).unwrap_or(i32::MAX),
                );
            }
            (
                TestType::TcpPing,
                ProbeOutcome::Ok {
                    latency_ms: None, ..
                },
            ) => {
                self.counters.fast_ok.fetch_add(1, Ordering::Relaxed);
            }
            (TestType::TcpPing, ProbeOutcome::Failed { class, hard, .. }) => {
                if *hard {
                    self.counters
                        .fast_hard_failed
                        .fetch_add(1, Ordering::Relaxed);
                    self.hard_fast
                        .lock()
                        .insert((link.protocol_id, link.endpoint_id));
                } else {
                    self.counters
                        .fast_soft_failed
                        .fetch_add(1, Ordering::Relaxed);
                }
                bump_class(&self.counters.fast_fail, *class);
            }
            (_, ProbeOutcome::Ok { .. }) => {
                self.counters.real_ok.fetch_add(1, Ordering::Relaxed);
            }
            (_, ProbeOutcome::Failed { text, class, .. }) => {
                // One counter, one meaning. A config-level refusal is
                // UNTESTABLE, not a failed probe: it used to land in
                // `real_failed`/`real_fail[Config]` while the plan-time
                // kind-level refusal incremented `untestable`, so one fact was
                // booked twice and a run line could read
                // `untestable=0 ... config=173` (2026-09-21, where the 173 were
                // exactly the persisted untestable markers).
                if is_untestable_text(text) {
                    self.counters.untestable.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters.real_failed.fetch_add(1, Ordering::Relaxed);
                    bump_class(&self.counters.real_fail, *class);
                }
            }
        }
        let (latency_ms, transport_ms, ip_info, error, purge, marker_kind) = match outcome {
            ProbeOutcome::Ok {
                latency_ms,
                transport_ms,
                ip_info,
            } => (
                *latency_ms,
                *transport_ms,
                ip_info.clone(),
                None,
                None,
                None,
            ),
            ProbeOutcome::Failed {
                text,
                evidence,
                transport_ms,
                transport_failed,
                ..
            } => (
                None,
                *transport_ms,
                None,
                Some(text.clone()),
                evidence.and_then(|ev| self.purge_for(link, ev)),
                // A TRANSPORT-stage failure is the `[fast]` marker even when
                // the probe was a real one (spec D1's "not measurable"
                // outcome): the transport never came up, so the row is not a
                // config verdict.
                transport_failed.then_some(leas_db::models::ProfileErr::Fast),
            ),
        };
        let endpoint_id = link.endpoint_id.get();
        let _ = self.tx.try_send(CoreEvent::TestTypeUpdate {
            endpoint_id,
            protocol_id: link.protocol_id.get(),
            test_type,
        });
        try_send_or_warn(
            &self.tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id: link.protocol_id.get(),
                test_type,
                latency_ms,
                transport_ms,
                speed_bps: None,
                ip_info,
                error,
                purge,
                marker_kind,
            },
            "batch_ping_result",
        );
    }

    /// One task settled: the level's `done` advances (with a rate sample for the
    /// ETA) and the waiter is woken when nothing of that level is outstanding.
    fn note_settled(&self, kind: TaskKind) {
        match kind {
            TaskKind::FastPing => {
                self.mark_settled(&self.fast_ended_ms);
                if self.pending_fast.fetch_sub(1, Ordering::Relaxed) == 1 {
                    self.settled.notify_waiters();
                }
            }
            TaskKind::RealPing => {
                self.mark_settled(&self.real_ended_ms);
                if self.pending_real.fetch_sub(1, Ordering::Relaxed) == 1 {
                    self.settled.notify_waiters();
                }
            }
            _ => {}
        }
    }

    /// One candidate's real half reached a terminal state (probe, sibling
    /// retire, stop retire): the level's `done` advances. Every link counted
    /// into `real.total` reaches this exactly once.
    fn note_real_done(&self) {
        Self::bump(&self.meters.main, &self.rate_main);
    }

    /// Emit the persisted `[real]` marker for a link the native engine cannot
    /// serve (kind-level gate, decided at plan time).
    ///
    /// Called from [`Self::after_fast_settle`], i.e. right after that link's fast
    /// result: the reverse order would let the fast success (which writes
    /// `error = None`) clear the marker.
    fn emit_untestable_marker(&self, link: &ProfileStats, text: &str) {
        // Persist from the link's own snapshot: the events handler only stages
        // what the loaded page still holds.
        self.stage_result(
            link,
            TestType::RealPing,
            &ProbeOutcome::soft_failure(text.to_string()),
        );
        let (protocol_id, endpoint_id) = (link.protocol_id.get(), link.endpoint_id.get());
        let _ = self.tx.try_send(CoreEvent::TestTypeUpdate {
            endpoint_id,
            protocol_id,
            test_type: TestType::RealPing,
        });
        try_send_or_warn(
            &self.tx,
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type: TestType::RealPing,
                latency_ms: None,
                transport_ms: None,
                speed_bps: None,
                ip_info: None,
                error: Some(text.to_string()),
                purge: None,
                marker_kind: None,
            },
            "untestable_marker",
        );
    }
}

// ── Entry points ───────────────────────────────────────────────────────────

/// Build the per-link plan for the currently selected endpoint (collapsed
/// multi-protocol rows).
fn plan_selected_endpoint(state: &AppState) -> Vec<PlanLink> {
    let Some(ep_id) = state.selected_profile_id() else {
        return Vec::new();
    };
    state
        .endpoints
        .iter()
        .find(|r| r.endpoint.id.get() == ep_id)
        .map(|row| plan_row_links(row).collect())
        .unwrap_or_default()
}

fn plan_row_links(row: &EndpointRow) -> impl Iterator<Item = PlanLink> + '_ {
    // One clone of the endpoint per ROW: every link of this endpoint shares it
    // (`Arc::clone` per link instead of a `String`-carrying `Endpoint` clone).
    let endpoint = Arc::new(row.endpoint.clone());
    row.links.iter().filter_map(move |link| {
        let protocol = row.protocols.get(&link.protocol_id)?.clone();
        Some(PlanLink {
            link: link.clone(),
            endpoint: Arc::clone(&endpoint),
            addresses: row.resolved_ips.clone(),
            protocol,
        })
    })
}

/// Batch fast-ping every link in the database.
pub fn start_batch_ping(state: &mut AppState) {
    start_batch(state, PlanSource::Feed(PlanScope::All), false, false);
}

/// Batch fast-ping every link in the database, then real-ping each link.
///
/// With `real_ping_test_all_protocols` unset (default), one successful real
/// ping on an endpoint retires the remaining links' real tasks.
pub fn start_batch_then_real_ping(state: &mut AppState) {
    let dedup = !state.config.speed_test.real_ping_test_all_protocols;
    start_batch(state, PlanSource::Feed(PlanScope::All), true, dedup);
}

/// Fast + real over one SCOPE of the feed.
///
/// The scope narrows which ENDPOINTS the walk visits (`rank_bin`, materialized
/// by ADR 0003); every link of a selected endpoint is planned, so a scope is a
/// plan filter and nothing about the per-link pipeline changes. Dedup is the
/// same setting the unscoped variant uses.
pub fn start_batch_then_real_ping_scoped(state: &mut AppState, scope: PlanScope) {
    let dedup = !state.config.speed_test.real_ping_test_all_protocols;
    start_batch(state, PlanSource::Feed(scope), true, dedup);
}

/// Fast-ping every link of the selected endpoint (collapsed multi-protocol rows).
pub fn start_endpoint_batch_ping(state: &mut AppState) {
    let plan = plan_selected_endpoint(state);
    start_batch(state, PlanSource::Links(plan), false, false);
}

/// Fast-ping then real-ping every link of the selected endpoint. `dedup` is
/// off: every protocol of the endpoint gets a real ping (their exit IPs may
/// differ).
pub fn start_endpoint_batch_real_ping(state: &mut AppState) {
    let plan = plan_selected_endpoint(state);
    start_batch(state, PlanSource::Links(plan), true, false);
}

/// Fill the exit IPs of a scope's links — its OWN command, its own scope, its
/// own bar and its own rate limiter (spec D10/D11, T3.6).
///
/// The exit IP is an INDEPENDENT fact: it ages on its own, and this command
/// NEVER rewrites the Real delay. A row that was measured keeps its real
/// span; a row that was not stays unmeasured — the fill adds a fact, it does
/// not replace one.
///
/// Its own rate limiter, and it is a THROTTLED one: the free IP-API tiers
/// publish ~45 requests/minute (ip-api), and a feed-wide fill would ask for
/// thousands. The limiter is the difference between a fill that works and a
/// fill that is refused by every provider.
pub fn start_fill_exit_ips(state: &mut AppState, scope: PlanScope) {
    // A feed-wide plan is loaded by the fill task (off the UI thread).
    if state.batch_progress.is_some() {
        state.log_trace("warn", "tui::ops::ping", "A batch is already running");
        return;
    }
    state.speed_test_stop.store(false, Ordering::Relaxed);
    state.scheduler.reset();
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let db = state.db.clone();
    let writer = state.link_stage.clone();
    let stop = state.speed_test_stop.clone();
    let ip_provider = state.config.speed_test.ip_provider;
    let meters = Arc::new(crate::types::BatchMeters::default());
    state.batch_progress = Some(Arc::clone(&meters));
    tokio::spawn(run_fill_exit_ips(FillExitIpsParams {
        db,
        writer,
        tx,
        stop,
        meters,
        scope,
        ip_provider,
    }));
}

/// The fill's parameters.
struct FillExitIpsParams {
    db: Arc<Database>,
    writer: Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    tx: mpsc::Sender<CoreEvent>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    meters: Arc<crate::types::BatchMeters>,
    scope: PlanScope,
    ip_provider: IpProvider,
}

/// The fill's own rate limiter: one exit-IP request every
/// [`EXIT_IP_FILL_INTERVAL`].
///
/// The free tiers publish ~45 requests/minute, so a fill that asks as fast
/// as it can is refused by every provider. The interval is the fill's
/// correctness constraint, not a politeness knob.
const EXIT_IP_FILL_INTERVAL: Duration = Duration::from_millis(1_500);

/// Fill the exit IPs of a scope's links.
///
/// A SEPARATE pipeline, not a batch mode: it never probes, never writes a
/// real delay and never writes an error marker for a config it did not test.
/// It writes the exit IP, the country flag (live, through the enrich path)
/// and — where the transport was observed — the Fast delay.
async fn run_fill_exit_ips(params: FillExitIpsParams) {
    let FillExitIpsParams {
        db,
        writer,
        tx,
        stop,
        meters,
        scope,
        ip_provider,
    } = params;
    // The scope's endpoints, read once. The fill is a SEPARATE, resumable
    // command — a provider rate limit ends one provider's turn, not the fill.
    let request = leas_db::profiles_query::PageRequest {
        view: leas_db::models::PurgatoryView::All,
        active_threshold: 0,
        scope,
        search: None,
        group_id: None,
        sort: FEED_SORT,
        ascending: true,
        offset: 0,
        limit: usize::MAX,
    };
    let page = match db.profiles_page(&request).await {
        Ok(page) => page,
        Err(e) => {
            tracing::warn!(target: "tui::ops::ping", "exit-IP fill: plan failed: {e}");
            let _ = tx.try_send(CoreEvent::BatchEnded);
            return;
        }
    };
    let ids = page.ids;
    meters.plan_pages_total.store(1, Ordering::Relaxed);
    meters.plan_pages_done.store(0, Ordering::Relaxed);
    let rows = match db.load_page_projection(&ids, false).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(target: "tui::ops::ping", "exit-IP fill: load failed: {e}");
            let _ = tx.try_send(CoreEvent::BatchEnded);
            return;
        }
    };
    meters.plan_pages_done.store(1, Ordering::Relaxed);
    // The links to fill: the scope's links, in the walk's order. The endpoint
    // rows come from the same projection the batch's walk uses, so the fill
    // dials the same addresses the probe would.
    let plans: Vec<(ProfileStats, Endpoint, Vec<std::net::IpAddr>)> = rows
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
    meters
        .main
        .total
        .store(plans.len() as u32, Ordering::Relaxed);
    let total = plans.len() as u32;
    let mut done = 0u32;
    for (link, endpoint, addresses) in plans {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // The rate limiter: one request per interval, for the whole fill.
        tokio::time::sleep(EXIT_IP_FILL_INTERVAL).await;
        let Some(protocol) = load_protocol_with_config(&db, link.protocol_id)
            .await
            .ok()
            .flatten()
        else {
            done += 1;
            meters.main.done.store(done, Ordering::Relaxed);
            continue;
        };
        // The probe target is a placeholder: the exit-IP fetch dials the
        // PROXY server and asks the provider through it.
        let Some(target) = ping_native::parse_probe_url("http://127.0.0.1/").ok() else {
            done += 1;
            meters.main.done.store(done, Ordering::Relaxed);
            continue;
        };
        let params =
            ping_native::probe_params(&endpoint, &addresses, &protocol.config.get().0, &target);
        let ip_info = ping_native::fetch_exit_ip(&params, ip_provider).await;
        done += 1;
        meters.main.done.store(done, Ordering::Relaxed);
        if let Some(ip_info) = ip_info {
            // The exit IP and the country flag — NEVER the real delay (spec
            // D11). The row keeps the real measurement it already had.
            let mut row = link.clone();
            if let Some(ip) = ip_info
                .split('|')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                row.latency.ip = Some(ip.to_string());
            }
            writer.stage(&row, leas_db::LinkGroups::RESULT);
            let _ = tx.try_send(CoreEvent::SpeedTestResult {
                endpoint_id: link.endpoint_id.get(),
                protocol_id: link.protocol_id.get(),
                test_type: TestType::RealPing,
                latency_ms: None,
                transport_ms: None,
                speed_bps: None,
                ip_info: Some(ip_info),
                error: None,
                purge: None,
                marker_kind: None,
            });
        }
    }
    // The writer flushes the staged rows; the terminal event closes the bar.
    let _ = writer.flush().await;
    let _ = tx.try_send(CoreEvent::BatchEnded);
    tracing::info!(
        target: "tui::ops::ping",
        "exit-IP fill: {done}/{total} link(s) processed"
    );
}

fn start_batch(state: &mut AppState, plan: PlanSource, real_phase: bool, dedup_endpoints: bool) {
    // A feed-wide plan is loaded by the batch task (off the UI thread), so only
    // an explicit plan can be known-empty here.
    if let PlanSource::Links(plan) = &plan
        && plan.is_empty()
    {
        state.log_trace(
            "info",
            "tui::ops::ping",
            if real_phase {
                "No profiles to test"
            } else {
                "No profiles to ping"
            },
        );
        return;
    }
    // Batches are serialized: the shared gate does not support two batches
    // racing to fire promoted tasks on the same link, and the progress bar
    // displays one batch.
    if state.batch_progress.is_some() {
        state.log_trace("warn", "tui::ops::ping", "A batch is already running");
        return;
    }
    // A fresh user gesture always starts with a clear stop flag AND a clear
    // gate: task ids are process-local and nothing from the previous batch is
    // live any more.
    state.speed_test_stop.store(false, Ordering::Relaxed);
    state.scheduler.reset();
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let runner: Arc<dyn BatchProbeRunner> = Arc::new(EngineProbeRunner);
    let db = state.db.clone();
    let writer = state.link_stage.clone();
    let scheduler = state.scheduler.clone();
    let stop = state.speed_test_stop.clone();
    // The meters hold no denominator until the walk fills one, which the status
    // bar renders as "Testing..." — and the batch handle published alongside
    // them is what says a batch is alive.
    let meters = Arc::new(crate::types::BatchMeters::default());
    state.batch_progress = Some(Arc::clone(&meters));
    let batch_slot: Arc<OnceLock<Arc<BatchShared>>> = Arc::new(OnceLock::new());
    state.batch = Some(batch_slot.clone());
    let fast_timeout = *state.config.speed_test.tcp_timeout_secs;
    let real_timeout = *state.config.speed_test.real_ping_timeout_secs;
    // The TRANSPORT stage's budget is the FAST level's timeout: the transport
    // stage measures the same thing the fast probe measures (the time to
    // establish the endpoint's transport), and the two budgets are INDEPENDENT
    // (spec D12) — a slow transport does not eat the protocol stage's budget.
    let transport_timeout = *state.config.speed_test.tcp_timeout_secs;
    let real_retries = state.config.speed_test.real_ping_retries;
    let ping_url = state.config.speed_test.ping_url.clone();
    let ip_provider = state.config.speed_test.ip_provider;
    let real_concurrency = state.config.speed_test.real_ping_concurrency.max(1);
    let error_ttl_hours = state.config.speed_test.error_ttl_hours;
    let dns_cache_ttl_secs = state.dns_cache_ttl_secs;
    // Sleep the full deferral window once, then re-schedule (the window is
    // measured in whole seconds and comes from the speed-test config via
    // `TaskScheduler::set_limits`).
    let defer_delay = Duration::from_secs(scheduler.dns_defer_secs().max(1) as u64);

    tokio::spawn(run_batch(BatchParams {
        scheduler,
        db,
        writer,
        tx,
        runner,
        stop,
        meters,
        plan,
        real_phase,
        dedup_endpoints,
        fast_timeout,
        real_timeout,
        transport_timeout,
        real_retries,
        ping_url,
        ip_provider,
        defer_delay,
        real_concurrency,
        page_size: PROFILES_PAGE_SIZE,
        error_ttl_hours,
        dns_cache_ttl_secs,
        batch_slot,
    }));
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;

    use leas_db::models::{ErrorInfo, Latency, ProfileErr};
    use tokio::sync::mpsc;

    use crate::ops::profiles::test_support::{fake_row, test_state};
    use crate::ops::scheduler::TaskScheduler;

    use super::*;

    use rstest::rstest;
    use std::io::ErrorKind;

    /// The reachable/unreachable decision over the typed facts of an IO failure.
    ///
    /// The old individual cases pinned the exact failures the 2026-09-27 Windows
    /// run produced (the strings the log carried and the kinds `std` folds the
    /// WSA codes onto), the localization invariance, the soft local/ambiguous
    /// set, the adapter-text fallback and the "a code is never re-read as text"
    /// arm — folding them into one (kind, code, text) → (class, hard) table keeps
    /// every one of those assertions as a named row. `None` for the kind is how
    /// a code `std` does not classify arrives here: `ErrorKind::Uncategorized`
    /// cannot be named on stable, so the classifier takes the absence instead,
    /// and the two Windows codes that matter (`11001`, `10040`) reach it exactly
    /// that way.
    #[rstest]
    #[case::timed_out_wsa_10060_rendered_in_russian(
        Some(ErrorKind::TimedOut),
        Some(10060),
        "Попытка установить соединение была безуспешной, т.к. от другого \
         компьютера за требуемое время не получен нужный отклик, или было разорвано \
         уже установленное соединение из-за неверного отклика уже подключенного \
         компьютера. (os error 10060)",
        ProbeClass::Timeout,
        true
    )]
    #[case::host_not_found_wsa_11001_uncategorized_by_std(
        None,
        Some(11001),
        "Этот хост неизвестен. (os error 11001)",
        ProbeClass::Dns,
        true
    )]
    #[case::connection_refused_wsa_10061_rendered_in_russian(
        Some(ErrorKind::ConnectionRefused),
        Some(10061),
        "Отказано в соединении. (os error 10061)",
        ProbeClass::Refused,
        true
    )]
    #[case::no_route_wsa_10065(
        Some(ErrorKind::HostUnreachable),
        Some(10065),
        "No route to host (os error 10065)",
        ProbeClass::NoRoute,
        true
    )]
    #[case::network_unreachable_wsa_10051_rendered_in_russian(
        Some(ErrorKind::NetworkUnreachable),
        Some(10051),
        "Сеть недоступна (os error 10051)",
        ProbeClass::Unreachable,
        true
    )]
    // Same kind and code, English rendering: identical verdict.
    #[case::timed_out_10060_english_text_same_verdict(
        Some(ErrorKind::TimedOut),
        Some(10060),
        "Connection timed out (os error 10060)",
        ProbeClass::Timeout,
        true
    )]
    // Same kind and code, Russian rendering: the text cannot soften it.
    #[case::timed_out_10060_russian_text_same_verdict(
        Some(ErrorKind::TimedOut),
        Some(10060),
        "Попытка установить соединение была безуспешной (os error 10060)",
        ProbeClass::Timeout,
        true
    )]
    // A firewall or AV block: something answered, it just said no.
    #[case::permission_denied_stays_soft(
        Some(ErrorKind::PermissionDenied),
        Some(10013),
        "whatever the OS said",
        ProbeClass::Io,
        false
    )]
    // A reset mid-exchange says something WAS there.
    #[case::connection_reset_stays_soft(
        Some(ErrorKind::ConnectionReset),
        Some(10054),
        "whatever the OS said",
        ProbeClass::Io,
        false
    )]
    // The QUIC send-path code from the same run (WSAEMSGSIZE).
    #[case::quic_send_path_10040_stays_soft(
        None,
        Some(10040),
        "whatever the OS said",
        ProbeClass::Io,
        false
    )]
    // fd exhaustion is a local resource problem.
    #[case::fd_exhaustion_10024_stays_soft(
        None,
        Some(10024),
        "whatever the OS said",
        ProbeClass::Io,
        false
    )]
    // An adapter message with no `io::Error` behind it still reaches the text
    // match, so the quic adapter's `DNS: …` wrapper keeps its class.
    #[case::adapter_dns_wrapper_without_a_code_falls_back_to_text(
        None,
        None,
        "DNS: failed to lookup address information: Name or service not known",
        ProbeClass::Dns,
        true
    )]
    // An error that DOES carry a code is never re-read as text: a message that
    // happens to contain an English-looking phrase must not reclassify a
    // failure the typed facts already decided.
    #[case::a_coded_failure_is_never_reclassified_by_its_text(
        None,
        Some(10040),
        "Connection refused (os error 10040)",
        ProbeClass::Io,
        false
    )]
    fn classify_io_failure_over_typed_facts(
        #[case] kind: Option<ErrorKind>,
        #[case] code: Option<i32>,
        #[case] text: &str,
        #[case] want: ProbeClass,
        #[case] hard: bool,
    ) {
        let (class, got_hard) = classify_io_failure(kind, code, text);
        assert_eq!(class, want, "class for kind {kind:?} / code {code:?}");
        assert_eq!(got_hard, hard, "hardness for kind {kind:?} / code {code:?}");
    }

    /// `std`'s WSA → `ErrorKind` folding is the assumption the whole typed path
    /// rests on, and it is only observable where those codes exist.
    #[cfg(windows)]
    #[test]
    fn std_maps_the_wsa_codes_the_classifier_depends_on() {
        for (code, want) in [
            (10060, ErrorKind::TimedOut),
            (10061, ErrorKind::ConnectionRefused),
            (10065, ErrorKind::HostUnreachable),
            (10051, ErrorKind::NetworkUnreachable),
        ] {
            assert_eq!(
                std::io::Error::from_raw_os_error(code).kind(),
                want,
                "os error {code}"
            );
        }
        // The two the classifier handles by code because std does not fold
        // them: a name that does not resolve, and a datagram that did not fit.
        for code in [11001, 10040] {
            let kind = std::io::Error::from_raw_os_error(code).kind();
            assert_eq!(
                classify_io_failure(None, Some(code), "x"),
                if code == 11001 {
                    (ProbeClass::Dns, true)
                } else {
                    (ProbeClass::Io, false)
                },
                "os error {code} classified off its kind {kind:?}"
            );
        }
    }

    /// The gate is open in BOTH modes now that the MVCC passive-checkpoint flag
    /// accompanies the MVCC opt-in (`file_driver`). It was `!concurrent_writes`
    /// because the engine rejected the statement under MVCC; inverting it is the
    /// point of that fix.
    #[test]
    fn checkpoint_runs_under_both_journal_modes() {
        assert!(wal_checkpoint_enabled(true), "MVCC now checkpoints");
        assert!(wal_checkpoint_enabled(false), "WAL still checkpoints");
    }

    /// The per-call real outcome: the call INDEX picks the outcome.
    type RealByCall = Box<dyn Fn(usize) -> ProbeOutcome + Send>;

    /// Deterministic probe runner: fixed outcomes + call recording + an
    /// optional gate that blocks real probes (for the stop-mid-batch test).
    struct StubRunner {
        fast_outcome: ProbeOutcome,
        real_outcome: Mutex<ProbeOutcome>,
        fast_calls: Arc<AtomicUsize>,
        real_calls: Arc<AtomicUsize>,
        real_gate: Mutex<Option<Arc<Notify>>>,
        /// When set, every fast probe marks the endpoint's DNS failure — used
        /// to land a deferral deterministically between phase 1 and phase 2.
        dns_mark_on_fast: Mutex<Option<(Arc<TaskScheduler>, EndpointId)>>,
        /// When set, every REAL probe marks the endpoint's DNS failure — the
        /// merged pipeline's deferral seam (the TCP fast probe is gone).
        dns_mark_on_real: Mutex<Option<(Arc<TaskScheduler>, EndpointId)>>,
        /// Per-address fast outcome, for the tests that need a mixed batch
        /// (an unreachable link next to a reachable one).
        fast_by_addr: Mutex<std::collections::HashMap<String, ProbeOutcome>>,
        /// Per-address fast delay, for the tests that need a deterministic
        /// fast-settle order (the real half is dispatched from that settle).
        fast_delay_by_addr: Mutex<std::collections::HashMap<String, Duration>>,
        /// Endpoint ids in the order their real probe STARTED.
        real_endpoint_order: Mutex<Vec<i64>>,
        /// When set, the real outcome is chosen by the CALL INDEX instead of
        /// the fixed one — the tests that need the first protocol to fail and
        /// the second to succeed (the group-entry barrier's deferral case).
        real_by_call: Mutex<Option<RealByCall>>,
    }

    impl StubRunner {
        fn new() -> Self {
            Self {
                fast_outcome: ProbeOutcome::Ok {
                    latency_ms: Some(10),
                    transport_ms: Some(10),
                    ip_info: None,
                },
                real_outcome: Mutex::new(ProbeOutcome::Ok {
                    latency_ms: Some(50),
                    transport_ms: Some(10),
                    ip_info: Some("1.2.3.4".to_string()),
                }),
                fast_calls: Arc::new(AtomicUsize::new(0)),
                real_calls: Arc::new(AtomicUsize::new(0)),
                real_gate: Mutex::new(None),
                dns_mark_on_fast: Mutex::new(None),
                dns_mark_on_real: Mutex::new(None),
                fast_by_addr: Mutex::new(std::collections::HashMap::new()),
                fast_delay_by_addr: Mutex::new(std::collections::HashMap::new()),
                real_endpoint_order: Mutex::new(Vec::new()),
                real_by_call: Mutex::new(None),
            }
        }

        /// Choose the real outcome by the CALL INDEX: the first call gets one
        /// outcome, the second another, and so on.
        ///
        /// The group-entry barrier's decisive case needs exactly this — the
        /// endpoint's first protocol fails and its second succeeds — and a
        /// per-address map cannot express it (both links share an address).
        fn set_real_outcome(&self, f: impl Fn(usize) -> ProbeOutcome + Send + 'static) {
            *self.real_by_call.lock() = Some(Box::new(f));
        }
    }

    impl BatchProbeRunner for StubRunner {
        fn fast<'a>(
            &'a self,
            _config_type: i32,
            addr: &'a str,
            _port: u16,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
            Box::pin(async move {
                self.fast_calls.fetch_add(1, Ordering::Relaxed);
                if let Some((sched, eid)) = &*self.dns_mark_on_fast.lock() {
                    sched.mark_dns_failure(*eid);
                }
                let delay = self.fast_delay_by_addr.lock().get(addr).copied();
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                if let Some(outcome) = self.fast_by_addr.lock().get(addr) {
                    return outcome.clone();
                }
                self.fast_outcome.clone()
            })
        }

        fn real<'a>(
            &'a self,
            endpoint: &'a Endpoint,
            _addresses: &'a [std::net::IpAddr],
            _config: &'a ProtocolConfig,
            _req: NativeProbeReq<'a>,
        ) -> Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>> {
            Box::pin(async move {
                let index = self.real_calls.fetch_add(1, Ordering::Relaxed);
                self.real_endpoint_order.lock().push(endpoint.id.get());
                // The merged pipeline's deferral seam: the DNS failure is
                // marked from the REAL probe, because the TCP fast probe no
                // longer runs in a real-phase batch.
                if let Some((sched, eid)) = &*self.dns_mark_on_real.lock() {
                    sched.mark_dns_failure(*eid);
                }
                // Clone the gate out of the lock so the await below does not
                // hold the mutex guard across the yield point.
                let gate = self.real_gate.lock().clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                // The per-call outcome wins when set: the group-entry
                // barrier's tests need the first call and the second to differ.
                if let Some(f) = self.real_by_call.lock().as_ref() {
                    return f(index);
                }
                self.real_outcome.lock().clone()
            })
        }
    }

    struct Harness {
        state: AppState,
        tx: mpsc::Sender<CoreEvent>,
        runner: Arc<StubRunner>,
    }

    /// D3: the "test all" entry point walks the FEED, and the walk plans no
    /// purged link — the real half is the long pole, and re-proving a link the
    /// classifier already judged is the one thing the purge exists to stop.
    /// The plan is the walk's output, so this is asserted at the walk (the
    /// batch always runs the real probe runner, which no stub counter sees).
    /// The selected-endpoint entry point reads the loaded page instead, so a
    /// Purgatory row is still testable by hand (the test below).
    #[tokio::test]
    async fn a_feed_sweep_plans_no_purged_link() {
        use leas_db::models::PurgeReason;

        let mut row = fake_row(1, "10.0.0.1", 2);
        row.links[1].purge_reason = Some(PurgeReason::NotTls);
        let live = row.links[0].protocol_id.get();
        let h = harness(vec![row]).await;

        let mut walk = PlanWalk::new(PlanSource::Feed(PlanScope::All), h.state.db.clone(), 10);
        let mut planned: Vec<i64> = Vec::new();
        while let Some(links) = walk.next_page().await.expect("walk page") {
            planned.extend(links.iter().map(|pl| pl.link.protocol_id.get()));
        }
        assert_eq!(
            planned,
            vec![live],
            "the purged link is not planned by a feed sweep"
        );
    }

    /// A plan scope narrows which ENDPOINTS the walk visits, so the plan — and
    /// therefore the probes — covers only the selected endpoints' links. The
    /// scope is the feed query plus a `rank_bin` predicate; this is the seam
    /// where the menu's scope reaches the SQL.
    #[tokio::test]
    async fn a_plan_scope_narrows_the_feed_walk() {
        use leas_db::models::{ErrorInfo, Latency, ProfileErr};

        // e1: a real success (tier 0) plus an untested sibling. The ring comes
        // WITH the real latency: `proven` (the Successful scope's membership)
        // is derived from the ring, and a real measurement is only ever written
        // by a real success — a `latency = Real` with an empty ring is a state
        // the law's invariant forbids.
        let mut successful = fake_row(1, "10.0.0.1", 2);
        successful.links[0].latency = Latency::real(30);
        successful.links[0].stab_mask = 1;
        successful.links[0].stab_len = 1;
        // e2: untested (tier 2).
        let untested = fake_row(2, "10.0.0.2", 1);
        // e3: a fast-error marker, nothing measured (tier 4).
        let mut failed = fake_row(3, "10.0.0.3", 1);
        failed.links[0].error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "timeout".into(),
        });

        let h = harness(vec![successful, untested, failed]).await;
        let planned_hosts = |scope| {
            let db = h.state.db.clone();
            async move {
                let mut walk = PlanWalk::new(PlanSource::Feed(scope), db, 100);
                let mut hosts: Vec<String> = Vec::new();
                while let Some(links) = walk.next_page().await.expect("walk page") {
                    hosts.extend(
                        links
                            .iter()
                            .map(|pl| dial_host(&pl.endpoint, &pl.addresses)),
                    );
                }
                hosts.sort();
                hosts.dedup();
                hosts
            }
        };

        assert_eq!(
            planned_hosts(PlanScope::Successful).await,
            vec!["10.0.0.1"],
            "only the endpoint with a real success"
        );
        assert_eq!(
            planned_hosts(PlanScope::SuccessfulAndNew).await,
            vec!["10.0.0.1", "10.0.0.2"],
            "the successful plus the untested endpoint"
        );
        assert_eq!(
            planned_hosts(PlanScope::New).await,
            vec!["10.0.0.2"],
            "only the endpoint nothing has answered for"
        );
        assert_eq!(
            planned_hosts(PlanScope::Failed).await,
            vec!["10.0.0.3"],
            "only the endpoint whose links all failed"
        );
        assert_eq!(
            planned_hosts(PlanScope::All).await,
            vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "the unscoped walk still covers the feed"
        );
    }

    /// A scoped walk freezes its endpoint set before any probe is dispatched.
    /// The scope predicate is the endpoint's `rank_bin`, which this run's own
    /// results change — so an offset-paged walk over the LIVE predicate skips
    /// every endpoint that leaves the scope mid-walk (which is most of a
    /// `Failed` run, whose whole purpose is to move endpoints to a success tier).
    #[tokio::test]
    async fn a_scoped_walk_freezes_its_set_before_probing() {
        use leas_db::models::Latency;

        let rows: Vec<EndpointRow> = (1..=4)
            .map(|i| {
                let mut row = fake_row(i, &format!("10.0.0.{i}"), 1);
                row.links[0].error = Some(ErrorInfo {
                    kind: ProfileErr::Fast,
                    text: "timeout".into(),
                });
                row
            })
            .collect();
        let h = harness(rows).await;

        let mut walk = PlanWalk::new(PlanSource::Feed(PlanScope::Failed), h.state.db.clone(), 1);
        let first = walk.next_page().await.expect("page").expect("a page");
        let mut planned: Vec<String> = first
            .iter()
            .map(|pl| dial_host(&pl.endpoint, &pl.addresses))
            .collect();

        // The batch's own results: the endpoints still unvisited would leave the
        // `Failed` scope now.
        for i in 2..=4 {
            let mut fixed = fake_row(i, &format!("10.0.0.{i}"), 1);
            fixed.links[0].latency = Latency::fast(10);
            h.state
                .db
                .upsert_link(&fixed.links[0])
                .await
                .expect("upsert the now-succeeding link");
        }

        while let Some(links) = walk.next_page().await.expect("page") {
            planned.extend(
                links
                    .iter()
                    .map(|pl| dial_host(&pl.endpoint, &pl.addresses)),
            );
        }
        planned.sort();
        assert_eq!(
            planned,
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            "every endpoint the walk started with is visited"
        );

        // …and the live predicate no longer matches them: the freeze is what
        // made the difference, not a scope that still held.
        let request = PageRequest {
            view: PurgatoryView::All,
            active_threshold: 0,
            scope: PlanScope::Failed,
            search: None,
            group_id: None,
            sort: PageSort::Port,
            ascending: true,
            offset: 0,
            limit: 10,
        };
        let live = h.state.db.profiles_page(&request).await.expect("page");
        assert_eq!(live.total, 1, "only the first endpoint still fails");
    }

    /// `PlanScope::All` used to stream by `PageSort::Id`, whose order no write
    /// can move. It now walks the decision-16 law — an order THIS BATCH rewrites
    /// as results land — so it must freeze too: without the freeze, every
    /// endpoint whose tier or latency improves mid-walk is skipped as the
    /// OFFSET slides past rows the walk never visited.
    #[tokio::test]
    async fn the_all_walk_freezes_before_probing_too() {
        use leas_db::models::Latency;

        let rows: Vec<EndpointRow> = (1..=4)
            .map(|i| fake_row(i, &format!("10.0.1.{i}"), 1))
            .collect();
        let h = harness(rows).await;

        let mut walk = PlanWalk::new(PlanSource::Feed(PlanScope::All), h.state.db.clone(), 1);
        let first = walk.next_page().await.expect("page").expect("a page");
        let mut planned: Vec<String> = first
            .iter()
            .map(|pl| dial_host(&pl.endpoint, &pl.addresses))
            .collect();
        assert_eq!(planned, ["10.0.1.1"], "the first page is one endpoint");

        // The batch's own results: every remaining endpoint now outranks the one
        // already dispatched, so a live-order walk would page past them.
        for i in 2..=4 {
            let mut fixed = fake_row(i, &format!("10.0.1.{i}"), 1);
            fixed.links[0].latency = Latency::fast(1);
            h.state
                .db
                .upsert_link(&fixed.links[0])
                .await
                .expect("upsert the now-measured link");
        }

        while let Some(links) = walk.next_page().await.expect("page") {
            planned.extend(
                links
                    .iter()
                    .map(|pl| dial_host(&pl.endpoint, &pl.addresses)),
            );
        }
        planned.sort();
        assert_eq!(
            planned,
            ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"],
            "the frozen set is walked in full even as the live order re-ranks"
        );
    }

    /// The selected-endpoint plan keeps purged links: it reads the loaded page,
    /// and the Purgatory view is where a purged link gets re-proved.
    #[tokio::test]
    async fn a_selected_endpoint_plan_keeps_purged_links() {
        use leas_db::models::{PurgatoryView, PurgeReason};

        let mut rows = vec![fake_row(1, "10.0.0.1", 2)];
        rows[0].links[0].purge_reason = Some(PurgeReason::NotTls);
        let mut h = harness(rows).await;
        h.state.purgatory_view = PurgatoryView::Purgatory;
        crate::ops::profiles::reload_profiles(&mut h.state).await;

        let plan = plan_selected_endpoint(&h.state);

        assert_eq!(plan.len(), 2, "both links are offered for a manual test");
    }

    /// An endpoint whose single link is a Shadowsocks row carrying a
    /// `mode=<plugin mode>` plugin. T24 needs a real QUIC row and a real
    /// WebSocket row side by side, so the two tests that share this helper
    /// differ only in the mode — the anti-overreach pair is meaningful exactly
    /// because everything else is identical.
    fn plugin_row(id: i64, host: &str, opts: &str) -> EndpointRow {
        use leas_db::models::{Protocol, Security, Transport};
        use leas_proto::proto_spec::common::SecurityConfig;
        use leas_proto::proto_spec::{
            PluginSpec, ProtocolConfig, ProtocolKind, SecurityType, SsConfig, TransportType,
        };
        use toasty::{Deferred, Json};

        let mut row = fake_row(id, host, 1);
        let link = row.links[0].clone();
        let protocol = Protocol {
            id: link.protocol_id,
            sig: link.protocol_id.get(),
            proto_kind: ProtocolKind::Shadowsocks,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: Some(PluginSpec::from_parts(Some("v2ray-plugin"), opts)),
            }))),
            created_at: crate::ops::profiles::test_support::ts(0),
            links: Deferred::default(),
        };
        row.protocols = std::collections::HashMap::from([(link.protocol_id, protocol)]);
        row
    }

    /// Row 11 / §8.1 item 4: the single-ping fast path reports **no TCP probe**
    /// for a datagram-mode row, and still probes every stream-mode one.
    ///
    /// Both directions are asserted because the dangerous failure here is
    /// SILENT: a gate written as "skip plugin rows" would satisfy the first half
    /// while quietly de-optimizing every `obfs=http` and `mode=websocket` row,
    /// and nothing in the UI would say so.
    #[test]
    fn a_datagram_plugin_row_declines_a_tcp_probe_and_a_stream_one_still_probes() {
        use leas_proto::proto_spec::common::SecurityConfig;
        use leas_proto::proto_spec::{PluginSpec, ProtocolConfig, SsConfig};

        let mode_of = |opts: &str| {
            let config = ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: Some(PluginSpec::from_parts(Some("v2ray-plugin"), opts)),
            });
            datagram_plugin_mode(&config)
        };

        assert_eq!(
            mode_of("mode=quic;host=cdn.example").as_deref(),
            Some("quic"),
            "a datagram row declares no meaningful TCP probe, by name"
        );
        for stream_mode in [
            "mode=websocket;host=cdn.example",
            "mode=websocket;host=cdn.example;mux=1",
            "mode=websocket;host=cdn.example;tls",
        ] {
            assert_eq!(
                mode_of(stream_mode),
                None,
                "{stream_mode} is a STREAM mode — skipping its TCP probe would \
                 de-optimize every ordinary plugin row"
            );
        }
        // A row with no plugin at all is likewise unaffected.
        assert_eq!(
            datagram_plugin_mode(&ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: None,
            })),
            None,
            "a plain shadowsocks row still takes the TCP fast probe"
        );
    }

    /// T24's subject: a `mode=quic` plugin row.
    fn quic_plugin_row(id: i64, host: &str) -> EndpointRow {
        plugin_row(id, host, "mode=quic;host=cdn.example")
    }

    async fn harness(rows: Vec<EndpointRow>) -> Harness {
        let mut state = test_state(rows.clone()).await;
        // Persist the plan rows so the scheduler gate (`write_task_state`
        // requires the row) and the real-probe protocol loads work.
        for row in &rows {
            // The page query drives from `endpoints` (joined to the stored
            // ordering keys), so a DB-backed plan needs the endpoint row too.
            state
                .db
                .upsert_endpoint(&row.endpoint)
                .await
                .expect("upsert endpoint");
            // db-rewamp D10: addresses live in `endpoint_ip`, and the feed
            // walk reads them back through the page query — without this a
            // fixture endpoint's dial host is empty.
            if !row.resolved_ips.is_empty() {
                state
                    .db
                    .update_endpoint_resolution(row.endpoint.id, row.resolved_ips.clone(), 1)
                    .await
                    .expect("resolution");
            }
            for link in &row.links {
                state.db.upsert_link(link).await.expect("upsert link");
                if let Some(proto) = row.protocols.get(&link.protocol_id) {
                    state
                        .db
                        .upsert_protocol(proto)
                        .await
                        .expect("upsert protocol");
                }
            }
        }
        let (tx, rx) = mpsc::channel(512);
        state.core_event_rx = Some(rx);
        state.core_event_tx = Some(tx.clone());
        let runner = Arc::new(StubRunner::new());
        Harness { state, tx, runner }
    }

    fn plan_from_rows(rows: &[EndpointRow]) -> Vec<PlanLink> {
        rows.iter().flat_map(plan_row_links).collect()
    }

    fn build_params(
        h: &Harness,
        plan: Vec<PlanLink>,
        real_phase: bool,
        dedup: bool,
    ) -> BatchParams {
        BatchParams {
            scheduler: h.state.scheduler.clone(),
            db: h.state.db.clone(),
            writer: h.state.link_stage.clone(),
            tx: h.tx.clone(),
            runner: h.runner.clone(),
            stop: h.state.speed_test_stop.clone(),
            meters: Arc::new(crate::types::BatchMeters::default()),
            plan: PlanSource::Links(plan),
            real_phase,
            dedup_endpoints: dedup,
            fast_timeout: Duration::from_secs(2),
            real_timeout: Duration::from_secs(2),
            transport_timeout: Duration::from_secs(2),
            real_retries: 1,
            ping_url: "http://127.0.0.1/".to_string(),
            ip_provider: IpProvider::IpApi,
            defer_delay: Duration::from_millis(50),
            real_concurrency: 8,
            // Tiny pages: the streaming walk is what a feed batch exercises.
            page_size: 2,
            error_ttl_hours: None,
            dns_cache_ttl_secs: h.state.dns_cache_ttl_secs,
            batch_slot: Arc::new(OnceLock::new()),
        }
    }

    fn start_test_batch(
        h: &mut Harness,
        plan: Vec<PlanLink>,
        real_phase: bool,
        dedup: bool,
    ) -> tokio::task::JoinHandle<()> {
        start_test_batch_with(h, plan, real_phase, dedup, 8)
    }

    /// Same, with the real level's concurrency pinned: one slot makes the real
    /// halves' order and the sibling-dedup decisions deterministic.
    fn start_test_batch_with(
        h: &mut Harness,
        plan: Vec<PlanLink>,
        real_phase: bool,
        dedup: bool,
        real_concurrency: usize,
    ) -> tokio::task::JoinHandle<()> {
        let mut p = build_params(h, plan, real_phase, dedup);
        p.real_concurrency = real_concurrency;
        h.state.batch_progress = Some(p.meters.clone());
        h.state.batch = Some(p.batch_slot.clone());
        tokio::spawn(run_batch(p))
    }

    /// Poll events until the batch's terminal `BatchEnded` clears the shared
    /// meters (or the deadline expires).
    async fn await_batch_done(state: &mut AppState) {
        for _ in 0..300 {
            let _ = state.poll_core_events().await;
            if state.batch_progress.is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("batch did not finish within the deadline");
    }

    /// The gate is the batch's only task-state authority, so "clear" means the
    /// scheduler no longer knows the link.
    fn assert_gate_clear(sched: &crate::ops::scheduler::TaskScheduler, link: &ProfileStats) {
        assert_eq!(
            sched.task_of(link),
            None,
            "gate must be clear after the batch"
        );
    }

    // ── phase 1 + phase 2 on a 3-link batch ─────────────────────────────

    /// A `Protocol` row is shared by every endpoint that carries the same
    /// config (identity ignores host/port), so the real half must load it once
    /// per batch rather than once per link: the load is a toasty query plus a
    /// JSON decode (measured 67–121 µs), i.e. 0.6–1.1 s over the 9k-link
    /// reference feed and 2.3–4.1 s over a 34k-link plan.
    #[tokio::test]
    async fn real_probe_loads_each_protocol_row_once_per_batch() {
        let first = fake_row(1, "10.0.0.1", 1);
        let mut second = fake_row(2, "10.0.0.2", 1);
        // One `Protocol` row, two endpoints: the second link points at the
        // first row's protocol id and carries that same `Protocol` snapshot.
        let shared_id = first.links[0].protocol_id;
        let protocol = first
            .protocols
            .get(&shared_id)
            .expect("fake_row links a protocol")
            .clone();
        second.links[0].protocol_id = shared_id;
        second.protocols.clear();
        second.protocols.insert(shared_id, protocol);

        let rows = vec![first, second];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        start_test_batch(&mut h, plan, true, false)
            .await
            .expect("batch");

        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            2,
            "both links got their real probe"
        );
        let shared = h
            .state
            .batch
            .as_ref()
            .and_then(|slot| slot.get())
            .expect("run_batch publishes its shared state");
        assert_eq!(
            shared.protocols.len(),
            1,
            "one load for the one protocol row the two links share"
        );
    }
    #[tokio::test]
    async fn dns_resolution_request_is_claimed_once_per_batch() {
        let row = fake_row(1, "example.test", 1);
        // already a DNS host
        let rows = vec![row];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let shared = Arc::new(BatchShared::new(build_params(&h, Vec::new(), false, false)));

        shared.dispatch_page(vec![plan[0].clone()]).await;
        shared.dispatch_page(vec![plan[0].clone()]).await;

        let receiver = h.state.core_event_rx.as_mut().expect("event receiver");
        let mut requests = 0;
        while let Ok(event) = receiver.try_recv() {
            if matches!(event, CoreEvent::DnsResolveRequest { .. }) {
                requests += 1;
            }
        }
        assert_eq!(requests, 1, "one DNS request per batch endpoint");
    }
    #[tokio::test]
    async fn batch_three_links_schedules_fast_then_real() {
        let rows = vec![
            fake_row(1, "10.0.0.1", 1),
            fake_row(2, "10.0.0.2", 1),
            fake_row(3, "10.0.0.3", 1),
        ];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        // The MERGED pipeline (spec D1): ONE probe per link. The TCP ping is
        // gone — the probe's own transport stage is the fast measurement, so a
        // real-phase batch never runs the fast probe at all.
        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            0,
            "a real-phase batch runs no separate TCP ping"
        );
        assert_eq!(h.runner.real_calls.load(Ordering::Relaxed), 3);
        for row in &h.state.endpoints {
            for link in &row.links {
                // Real ping superseded the fast latency; no error markers.
                assert_eq!(
                    link.latency,
                    Latency {
                        real_delay: Some(50),
                        fast_delay: Some(10),
                        ip: Some("1.2.3.4".to_string()),
                        auth: None,
                    },
                    "unexpected latency {link:?}"
                );
                assert!(link.error.is_none(), "no marker expected: {link:?}");
                assert_gate_clear(h.state.scheduler.as_ref(), link);
            }
        }
    }

    // ── the batch tests the feed, not the viewport ───────────────────────

    /// "All profiles" means the database, not the loaded page: the page is 200
    /// endpoint rows, so a page-scoped run tested 272 of the 4,523 links in the
    /// 2026-09-15 feed. The walk covers every page of the tab's query and hands
    /// them over one at a time — the batch dispatches each page as it loads.
    #[tokio::test]
    async fn the_plan_walk_covers_every_page_of_links() {
        let rows: Vec<EndpointRow> = (1..=5)
            .map(|i| fake_row(i, &format!("10.0.0.{i}"), 1))
            .collect();
        let h = harness(rows.clone()).await;

        // page_size 2 over 5 endpoints: three pages, one of them partial — the
        // walk must stop on the feed count, not on a short page.
        let mut walk = PlanWalk::new(PlanSource::Feed(PlanScope::All), h.state.db.clone(), 2);
        let mut hosts: Vec<String> = Vec::new();
        let mut pages = 0;
        while let Some(links) = walk.next_page().await.expect("walk page") {
            pages += 1;
            assert_eq!(
                walk.pages_total(),
                3,
                "the first page carries the feed-wide count"
            );
            hosts.extend(
                links
                    .iter()
                    .map(|pl| dial_host(&pl.endpoint, &pl.addresses)),
            );
        }
        assert_eq!(pages, 3, "5 endpoints at 2 per page");
        hosts.sort();
        let mut expected: Vec<String> = rows
            .iter()
            .map(|r| dial_host(&r.endpoint, &r.resolved_ips))
            .collect();
        expected.sort();
        assert_eq!(hosts, expected, "every link in the feed is planned");
    }

    /// A feed-scoped batch does not depend on the loaded page at all: with an
    /// empty page it still probes every link the database holds.
    #[tokio::test]
    async fn a_feed_batch_probes_links_outside_the_loaded_page() {
        let rows: Vec<EndpointRow> = (1..=3)
            .map(|i| fake_row(i, &format!("10.0.0.{i}"), 1))
            .collect();
        let mut h = harness(rows.clone()).await;
        h.state.endpoints.clear();

        let p = BatchParams {
            plan: PlanSource::Feed(PlanScope::All),
            ..build_params(&h, Vec::new(), false, false)
        };
        h.state.batch_progress = Some(p.meters.clone());
        run_batch(p).await;

        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            3,
            "the feed's links are probed even though the page is empty"
        );
        for row in &rows {
            let link = leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
                row.links[0].protocol_id,
                row.links[0].endpoint_id,
            )
            .first()
            .exec(&mut h.state.db.connection().await.expect("conn"))
            .await
            .expect("read")
            .expect("row");
            assert_eq!(
                link.latency,
                Latency::fast(10),
                "a feed link's result is persisted: {link:?}"
            );
        }
    }

    // ── the batch, not the page, is the record ───────────────────────────

    /// A batch persists its own results: the UI page is a view, and a page
    /// that no longer holds the row (an import moves every endpoint's ordering
    /// keys while the batch runs) must not cost the write. The handler used to
    /// be the only writer of a result, so every link it could not find in the
    /// loaded page was logged and dropped.
    #[tokio::test]
    async fn batch_persists_results_the_page_no_longer_holds() {
        let rows = vec![fake_row(1, "10.0.0.1", 1), fake_row(2, "10.0.0.2", 1)];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        // The page is replaced mid-batch: the events handler finds no row.
        h.state.endpoints.clear();

        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();

        // `finish_batch` flushes: the result is in the database.
        for row in &rows {
            let link = leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
                row.links[0].protocol_id,
                row.links[0].endpoint_id,
            )
            .first()
            .exec(&mut h.state.db.connection().await.expect("conn"))
            .await
            .expect("read")
            .expect("row");
            assert_eq!(
                link.latency,
                Latency {
                    real_delay: Some(50),
                    fast_delay: Some(10),
                    ip: Some("1.2.3.4".to_string()),
                    auth: None,
                },
                "the batch's own staging must persist the result: {link:?}"
            );
            assert!(link.error.is_none(), "no marker expected: {link:?}");
        }
    }

    // ── the transport failure is the retirement ─────────────────────────

    /// A link whose TRANSPORT stage failed (refused / unreachable /
    /// unresolvable / the stage-1 timeout) is retired: the probe cannot pass
    /// where the dial did not. A failure AFTER the transport (a TLS-level
    /// error, say) is NOT a retirement — the transport was up, and the config
    /// is what failed.
    ///
    /// The MERGED pipeline (spec D1): there is no separate fast phase to
    /// decide this. The probe's OWN stage decides it, through the
    /// `transport_failed` flag — never the class, because the stage-1 and the
    /// stage-2+ deadlines share the class `Timeout`.
    #[tokio::test]
    async fn a_transport_failure_retires_the_link_and_a_config_failure_does_not() {
        let rows = vec![
            fake_row(1, "10.0.0.1", 1),
            fake_row(2, "10.0.0.2", 1),
            fake_row(3, "10.0.0.3", 1),
        ];
        let mut h = harness(rows.clone()).await;
        // The transport stage failed for link 1; the protocol stage failed for
        // link 2; link 3 is fine.
        h.runner.set_real_outcome(|index| match index {
            0 => ProbeOutcome::Failed {
                text: "IO: Connection refused (os error 111)".to_string(),
                class: ProbeClass::Refused,
                hard: false,
                transport_ms: None,
                evidence: None,
                // A refused socket: the transport never came up.
                transport_failed: true,
            },
            1 => ProbeOutcome::Failed {
                text: "TLS error: handshake error: alert: 2 40".to_string(),
                class: ProbeClass::Tls,
                hard: false,
                transport_ms: Some(9),
                evidence: None,
                // The transport was up (it measured 9 ms); the CONFIG failed.
                transport_failed: false,
            },
            _ => ProbeOutcome::Ok {
                latency_ms: Some(50),
                transport_ms: Some(10),
                ip_info: Some("1.2.3.4".to_string()),
            },
        });
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            0,
            "the merged pipeline runs no separate TCP ping"
        );
        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            3,
            "every link gets ONE probe — the transport failure retires the ROW, not the probe"
        );

        let persisted = |row: &EndpointRow| {
            let (protocol_id, endpoint_id) = (row.links[0].protocol_id, row.links[0].endpoint_id);
            let db = h.state.db.clone();
            async move {
                leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
                    protocol_id,
                    endpoint_id,
                )
                .first()
                .exec(&mut db.connection().await.expect("conn"))
                .await
                .expect("read")
                .expect("row")
            }
        };

        // The transport-failed link: the `[fast]` marker (the transport never
        // came up — spec D1's "not measurable" outcome), and NO measurement.
        let skipped = persisted(&rows[0]).await;
        assert!(
            matches!(
                skipped.error.as_ref().map(|e| e.kind),
                Some(ProfileErr::Fast)
            ),
            "the transport-failed link keeps the `[fast]` marker: {skipped:?}"
        );
        assert_eq!(
            skipped.error.as_ref().map(|e| e.text.as_str()),
            Some("IO: Connection refused (os error 111)")
        );
        assert_eq!(
            skipped.latency,
            Latency::default(),
            "a transport failure measures nothing: {skipped:?}"
        );

        // The CONFIG-failed link: the transport was up, so it carries the
        // transport span BESIDE the `[real]` marker — "the server is up, the
        // config is not" (spec D12). This is the pair of facts the merged row
        // exists to show, and the old two-phase pipeline could not show it.
        let config_failed = persisted(&rows[1]).await;
        assert_eq!(
            config_failed.latency,
            Latency {
                real_delay: None,
                fast_delay: Some(9),
                ip: None,
                auth: None,
            },
            "the transport span survives the config failure: {config_failed:?}"
        );
        assert!(
            matches!(
                config_failed.error.as_ref().map(|e| e.kind),
                Some(ProfileErr::Real)
            ),
            "and a config failure is a `[real]` marker: {config_failed:?}"
        );

        // The healthy link: both measurements.
        let healthy = persisted(&rows[2]).await;
        assert_eq!(
            healthy.latency,
            Latency {
                real_delay: Some(50),
                fast_delay: Some(10),
                ip: Some("1.2.3.4".to_string()),
                auth: None,
            },
            "a probed link carries both measurements: {healthy:?}"
        );
    }

    // ── a phase-2 patch keeps the phase-1 measurement ───────────────────

    /// The RESULT group writes `latency` and `error` together, and every batch
    /// patch is built from the plan-time snapshot — so a phase-2 failure used
    /// to carry `latency = None` and erase the delay phase 1 had just measured
    /// for the same link (160 of 218 real failures lost it on 2026-09-15; the
    /// events handler used to mask this by staging from its live page row).
    #[tokio::test]
    async fn a_real_failure_keeps_the_fast_measurement() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let mut h = harness(rows.clone()).await;
        // The probe FAILED after its transport stage completed: the transport
        // span is 12 ms and the config did not work. The merged row keeps the
        // transport span beside the failure marker (spec D12).
        *h.runner.real_outcome.lock() = ProbeOutcome::Failed {
            text: "timeout on probe attempt (limit 5s)".to_string(),
            class: ProbeClass::Timeout,
            hard: false,
            evidence: None,
            transport_ms: Some(12),
            // The TRANSPORT was alive (it measured 12 ms) — the PROTOCOL
            // stage hung. This is NOT a transport failure, so the row is NOT
            // retired: the server is up and the config is what failed.
            transport_failed: false,
        };

        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();

        let link = leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
            rows[0].links[0].protocol_id,
            rows[0].links[0].endpoint_id,
        )
        .first()
        .exec(&mut h.state.db.connection().await.expect("conn"))
        .await
        .expect("read")
        .expect("row");
        assert_eq!(
            link.latency,
            Latency {
                real_delay: None,
                fast_delay: Some(12),
                ip: None,
                auth: None,
            },
            "the transport span survives a real-ping failure: {link:?}"
        );
        assert_eq!(
            link.error.as_ref().map(|e| e.kind),
            Some(ProfileErr::Real),
            "and the marker still lands: {link:?}"
        );
    }

    /// T24: a `mode=quic` plugin row reaches a REAL result.
    ///
    /// The fast level is a TCP handshake probe, and a QUIC server does not speak
    /// TCP — so every quic row's fast probe fails in a connect class, the
    /// retirement decision read that as "unreachable", and the real probe was
    /// never dispatched. The row was permanently `[fast]`-failed and untestable
    /// no matter what the server was. The fast probe still runs (it is cheap and
    /// its verdict may still be informative for other rows); only its RETIREMENT
    /// is wrong, and its marker is retracted because a TCP failure is not
    /// evidence about a QUIC server.
    #[tokio::test]
    async fn a_quic_plugin_row_is_not_retired_by_its_tcp_fast_failure() {
        let rows = vec![quic_plugin_row(1, "10.0.0.1")];
        let mut h = harness(rows.clone()).await;
        let params = build_params(&h, plan_from_rows(&rows), true, false);
        h.state.batch_progress = Some(params.meters.clone());
        let shared = Arc::new(BatchShared::new(params));
        let link = rows[0].links[0].clone();
        // The caches `run_batch`'s dispatch fills per page; calling the chain
        // directly means seeding the same entry, or the probe answers its
        // "Endpoint not found" soft failure and the test measures nothing.
        shared
            .endpoints
            .insert(link.endpoint_id, Arc::new(rows[0].endpoint.clone()));
        run_task_chain(Arc::clone(&shared), link.clone(), 0, TaskKind::FastPing).await;

        assert_eq!(
            shared.counters.unreachable.load(Ordering::Relaxed),
            0,
            "a quic row is NOT retired: its transport stage cannot measure a QUIC server \
             the way a TCP handshake could"
        );
        assert_eq!(
            shared.meters.main.done.load(Ordering::Relaxed),
            1,
            "the probe ran and settled — it is not retired"
        );
        // The verdict it reaches today is the capability gate's: `mode=quic` is
        // refused by name (T22 could not pin its wire from evidence), so the row
        // gets an `[untestable]` marker naming that reason. What must NOT come
        // back is a transport-derived `[fast]` verdict.
        assert_eq!(
            shared.counters.untestable.load(Ordering::Relaxed),
            1,
            "the capability gate produced the row's verdict"
        );
        let mut rx = h.state.core_event_rx.take().expect("event receiver");
        let mut real_text = String::new();
        // The probe emits a TestTypeUpdate and then its result, so read until
        // the result is in rather than counting events.
        for _ in 0..8 {
            if !real_text.is_empty() {
                break;
            }
            match rx.recv().await.expect("channel open") {
                CoreEvent::SpeedTestResult {
                    protocol_id,
                    test_type: TestType::RealPing,
                    error: Some(text),
                    ..
                } if protocol_id == link.protocol_id.get() => real_text = text,
                _ => {}
            }
        }
        assert!(
            crate::ops::ping::is_untestable_text(&real_text),
            "the row is marked untestable, not failed: {real_text:?}"
        );
    }

    // ── one summary line per batch ───────────────────────────────────────

    // ── stability samples (spec `2026-10-09-stab-bin-design` §7.1/§7.2) ──

    /// A real probe appends exactly one sample; a fast ping never does.
    #[tokio::test]
    async fn only_real_probes_sample_stability() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let shared = Arc::new(BatchShared::new(build_params(&h, plan, false, false)));
        let link = rows[0].links[0].clone();

        // A FAST result must not move the ring.
        shared.stage_result(
            &link,
            TestType::TcpPing,
            &ProbeOutcome::Ok {
                latency_ms: Some(12),
                transport_ms: Some(12),
                ip_info: None,
            },
        );
        assert!(
            shared
                .writer
                .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB))
                .is_none(),
            "a fast ping proves nothing about the config and must not sample"
        );

        // A REAL success appends one success.
        shared.stage_result(
            &link,
            TestType::RealPing,
            &ProbeOutcome::Ok {
                latency_ms: Some(40),
                transport_ms: Some(12),
                ip_info: None,
            },
        );
        let staged = shared
            .writer
            .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB))
            .expect("real success samples");
        assert_eq!((staged.link.stab_mask, staged.link.stab_len), (1, 1));

        // A REAL failure appends one failure to the SAME ring (read-through).
        shared.stage_result(
            &link,
            TestType::RealPing,
            &ProbeOutcome::Failed {
                text: "timeout".to_string(),
                class: ProbeClass::Timeout,
                hard: false,
                transport_ms: None,
                evidence: None,
                transport_failed: false,
            },
        );
        let staged = shared
            .writer
            .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB))
            .expect("real failure samples");
        assert_eq!(
            (staged.link.stab_mask, staged.link.stab_len),
            (0b01, 2),
            "the failure appends to the ring the success opened"
        );
    }

    /// The untestable marker is NOT a probe: it must not accrue an attempt.
    #[tokio::test]
    async fn an_untestable_marker_never_samples_stability() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let shared = Arc::new(BatchShared::new(build_params(&h, plan, false, false)));
        let link = rows[0].links[0].clone();
        shared.stage_result(
            &link,
            TestType::RealPing,
            &ProbeOutcome::soft_failure(untestable_marker_text("flow is not supported")),
        );
        assert!(
            shared
                .writer
                .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB))
                .is_none(),
            "the capability gate refused the row; no probe ran, so no sample"
        );
    }

    /// A hard-fast retirement samples ONLY in a real-capable batch (F1): in a
    /// fast-only pass it would fill rings with failures no real probe can
    /// offset, silently demoting proven links.
    #[tokio::test]
    async fn the_retirement_sample_is_gated_on_the_real_phase() {
        for real_phase in [false, true] {
            let rows = vec![fake_row(1, "10.0.0.1", 1)];
            let h = harness(rows.clone()).await;
            let plan = plan_from_rows(&rows);
            let shared = Arc::new(BatchShared::new(build_params(&h, plan, real_phase, false)));
            let link = rows[0].links[0].clone();
            shared
                .hard_fast
                .lock()
                .insert((link.protocol_id, link.endpoint_id));
            shared.after_fast_settle(&link).await;
            let staged = shared
                .writer
                .get(&(link.protocol_id, link.endpoint_id, LinkGroups::STAB));
            if real_phase {
                let staged = staged.expect("a real-capable batch samples the retirement");
                assert_eq!(
                    (staged.link.stab_mask, staged.link.stab_len),
                    (0, 1),
                    "the retirement appends one FAILURE"
                );
            } else {
                assert!(
                    staged.is_none(),
                    "a fast-only pass must not sample a retirement"
                );
            }
        }
    }

    /// The batch's record is ONE line carrying every counter: per-result lines
    /// moved to `debug` (a 5-minute run wrote 32k of them on 2026-09-15, and
    /// reconstructing the run from them was the whole cost of the
    /// investigation). This pins the record's fields so a later edit cannot
    /// drop one silently.
    #[tokio::test]
    async fn the_batch_summary_reports_every_counter() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let params = build_params(&h, plan, true, false);
        let meters = params.meters.clone();
        let shared = BatchShared::new(params);
        let counters = &shared.counters;
        meters.main.total.store(4, Ordering::Relaxed);
        counters.fast_ok.store(7, Ordering::Relaxed);
        counters.fast_hard_failed.store(5, Ordering::Relaxed);
        counters.fast_soft_failed.store(3, Ordering::Relaxed);
        counters.real_ok.store(2, Ordering::Relaxed);
        counters.real_failed.store(4, Ordering::Relaxed);
        counters.untestable.store(1, Ordering::Relaxed);
        counters.unreachable.store(5, Ordering::Relaxed);
        counters.deferred.store(6, Ordering::Relaxed);
        counters.queue_full.store(8, Ordering::Relaxed);
        shared.plan_ms.store(120, Ordering::Relaxed);
        shared.fast_started_ms.store(3, Ordering::Relaxed);
        shared.fast_ended_ms.store(180, Ordering::Relaxed);
        shared.real_started_ms.store(60, Ordering::Relaxed);
        shared.real_ended_ms.store(340, Ordering::Relaxed);
        // The classes are what a fix is aimed at: `hard-fail=5` alone cannot
        // say whether the run failed on timeouts, DNS or refusals.
        bump_class(&counters.fast_fail, ProbeClass::Timeout);
        bump_class(&counters.fast_fail, ProbeClass::Timeout);
        bump_class(&counters.fast_fail, ProbeClass::Dns);
        bump_class(&counters.real_fail, ProbeClass::Tls);

        let line = summary_line(&shared);
        for expected in [
            "links=4",
            "plan=120 ms",
            "untestable=1",
            "queue-full=8",
            "deferred=6",
            "fast ok=7 hard-fail=5 soft-fail=3 [timeout=2 dns=1] (3..180 ms)",
            "real ok=2 failed=4 [tls=1] skipped-unreachable=5 (60..340 ms)",
            "stopped=false",
            "staged-left=0",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in: {line}");
        }
    }

    /// T5's fail-closed arm, which sat untested inside a closure that was
    /// duplicated verbatim at two sites — so a test at one would not have
    /// covered the other, and a future `unwrap_or_default()` on the guard would
    /// have flipped the rule to fail-open with nothing failing.
    ///
    /// A cache MISS must earn NO verdict: failing open would let an approximated
    /// probe earn exactly the permanent Purgatory verdict the rule exists to
    /// prevent, and Purgatory is the one output that is not cheaply reversible.
    #[tokio::test]
    async fn a_protocol_cache_miss_earns_no_verdict_and_a_cached_fp_decides_it() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let h = harness(rows.clone()).await;
        let params = build_params(&h, plan_from_rows(&rows), true, false);
        let shared = BatchShared::new(params);
        let link = rows[0].links[0].clone();
        let config = rows[0].protocols[&link.protocol_id].config.get().0.clone();
        let evidence = leas_native::error::FailureEvidence::RealityFallback;
        let cache = |fp: Option<&str>| {
            shared.protocols.insert(
                link.protocol_id,
                Arc::new(LoadedProtocol {
                    kind: leas_proto::proto_spec::ProtocolKind::Vless,
                    config: config.clone(),
                    fp: fp.map(str::to_string),
                }),
            );
        };

        // A miss: no verdict at all, even for evidence that otherwise purges.
        assert_eq!(
            shared.purge_for(&link, evidence),
            None,
            "a cache miss must fail CLOSED"
        );

        // Cached and honoured: the verdict stands.
        cache(Some("chrome"));
        assert_eq!(
            shared.purge_for(&link, evidence),
            Some(leas_db::models::PurgeReason::RealityFallback)
        );

        // Cached and approximated: no verdict, because the shape dialled is not
        // the shape the link asked for.
        for fp in ["qq", "android", "hellochrome_120"] {
            cache(Some(fp));
            assert_eq!(
                shared.purge_for(&link, evidence),
                None,
                "{fp} must earn no verdict"
            );
        }

        // Cached with no fingerprint requested: honoured, so the verdict stands.
        cache(Some(""));
        assert_eq!(
            shared.purge_for(&link, evidence),
            Some(leas_db::models::PurgeReason::RealityFallback),
            "an empty fp requested no fingerprint, so the default is the shape asked for"
        );
    }

    /// T7: one counter, one meaning. A config-level refusal is UNTESTABLE, not
    /// a failed probe. Both used to be booked — the plan-time kind gate
    /// incremented `untestable` while a config-level refusal incremented
    /// `real_failed` and `real_fail[Config]` — which is why the 2026-09-21 run
    /// line read `untestable=0 … config=173` where the 173 were exactly the
    /// persisted untestable markers.
    #[tokio::test]
    async fn a_config_level_refusal_counts_as_untestable_not_as_a_failed_probe() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let h = harness(rows.clone()).await;
        let params = build_params(&h, plan_from_rows(&rows), true, false);
        let shared = BatchShared::new(params);
        let link = rows[0].links[0].clone();

        shared.emit_result(
            &link,
            TestType::RealPing,
            &ProbeOutcome::soft_failure(untestable_marker_text(
                "vless account encryption is not implemented",
            )),
        );
        assert_eq!(
            shared.counters.untestable.load(Ordering::Relaxed),
            1,
            "a config-level refusal is untestability"
        );
        assert_eq!(
            shared.counters.real_failed.load(Ordering::Relaxed),
            0,
            "and it is NOT a failed probe — one fact, one counter"
        );
        assert!(
            shared.counters.real_fail.lock().is_empty(),
            "so it contributes no failure class either"
        );

        // A genuine failure still counts as one, so the fix cannot be "count
        // everything as untestable".
        shared.emit_result(
            &link,
            TestType::RealPing,
            &ProbeOutcome::soft_failure("timeout on probe attempt (limit 5s)"),
        );
        assert_eq!(shared.counters.real_failed.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared.counters.untestable.load(Ordering::Relaxed),
            1,
            "and the untestable count did not move"
        );
    }

    // ── error-TTL sweep at batch completion ──────────────────────────────
    #[tokio::test]
    async fn batch_completion_sweeps_stale_error_markers() {
        // A link with a persisted error whose updated_at predates the TTL.
        // The batch is stopped before dispatch, so no probe touches the link
        // — the `finish_batch` sweep must clear the stale marker from the DB
        // (links the batch never re-tests are exactly the ones it clears).
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let mut h = harness(rows.clone()).await;
        let mut link = h.state.endpoints[0].links[0].clone();
        link.error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "old failure".to_string(),
        });
        h.state.db.upsert_link(&link).await.expect("upsert link");
        let mut conn = h.state.db.connection().await.unwrap();
        leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
            link.protocol_id,
            link.endpoint_id,
        )
        .update()
        .updated_at(jiff::Timestamp::now().as_second() - 48 * 3600)
        .exec(&mut conn)
        .await
        .unwrap();

        let plan = plan_from_rows(&rows);
        let mut params = build_params(&h, plan, false, false);
        params.error_ttl_hours = Some(24);
        h.state.batch_progress = Some(params.meters.clone());
        h.state.speed_test_stop.store(true, Ordering::Relaxed);
        tokio::spawn(run_batch(params)).await.unwrap();
        await_batch_done(&mut h.state).await;

        // The batch's staged patches are the only place its result lives until
        // the flush: make them durable, then read the row back.
        h.state.link_stage.flush().await.expect("flush");
        let stored = h
            .state
            .db
            .read_link_row(link.protocol_id, link.endpoint_id)
            .await
            .expect("read link")
            .expect("link persisted");
        assert!(
            stored.error.is_none(),
            "stale marker swept at batch completion: {stored:?}"
        );
    }

    #[tokio::test]
    async fn fast_dedup_fans_out_to_links_sharing_address() {
        // Two links on one endpoint share the (address, port) key: one TCP
        // ping, result fanned to both links.
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, false, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            1,
            "one TCP ping per unique address"
        );
        for link in &h.state.endpoints[0].links {
            assert!(matches!(
                link.latency,
                Latency {
                    fast_delay: Some(10),
                    ..
                }
            ));
            assert!(link.error.is_none());
            assert_gate_clear(h.state.scheduler.as_ref(), link);
        }
    }

    // ── sibling dedup (dedup_endpoints, best-effort) ─────────────────────

    /// The GROUP-ENTRY barrier (spec D15/T3.1): the endpoint's links are
    /// probed ONE AT A TIME, and the endpoint's verdict decides whether the
    /// siblings are probed at all.
    ///
    /// The decisive property: a sibling that is DEFERRED (the endpoint's first
    /// protocol did not succeed) is still probed — there is no second barrier
    /// check, so an endpoint whose first config failed still gets its other
    /// configs measured. A sibling that is SKIPPED (the endpoint's first
    /// protocol succeeded) is never probed and never writes a marker.
    ///
    /// This is the merged pipeline's throughput premise: the endpoint's
    /// working config is found first, and the endpoint's other configs are
    /// only probed when the first one did not work.
    #[tokio::test]
    async fn a_deferred_sibling_is_probed_when_it_is_reached() {
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        // The endpoint's FIRST protocol fails; the second succeeds. The
        // sibling must still be probed — the barrier is consulted at group
        // entry, and a failed first protocol does not suppress the siblings.
        h.runner.set_real_outcome(|index| match index {
            0 => ProbeOutcome::Failed {
                text: "timeout".to_string(),
                class: ProbeClass::Timeout,
                hard: false,
                evidence: None,
                transport_ms: Some(12),
                // The transport was alive; the protocol stage failed.
                transport_failed: false,
            },
            _ => ProbeOutcome::Ok {
                latency_ms: Some(50),
                transport_ms: Some(10),
                ip_info: Some("1.2.3.4".to_string()),
            },
        });
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch_with(&mut h, plan, true, true, 1);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            2,
            "a failed first protocol must not suppress the sibling: the deferred sibling is probed"
        );
        // The FAILED link keeps its transport span beside the marker — the
        // merged row's whole point (spec D12).
        let links = &h.state.endpoints[0].links;
        let failed = links
            .iter()
            .find(|l| l.error.is_some())
            .expect("the first protocol's failure is recorded");
        assert_eq!(
            failed.latency.fast_delay,
            Some(12),
            "the transport span survives the failure: the server was up, the config was not"
        );
        assert_eq!(
            failed.latency.real_delay, None,
            "a failed probe has no real span"
        );
    }

    /// The group's dropped siblings SETTLE: the denominator and the
    /// numerator meet.
    ///
    /// A held sibling was counted into `main.total` at plan time, so a
    /// dropped one must be counted into `main.done` — otherwise the batch's
    /// waiter waits out the whole deferral budget for a link that will never
    /// settle, and the bar never reaches its total.
    #[tokio::test]
    async fn a_dropped_group_sibling_still_settles_its_meter() {
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch_with(&mut h, plan, true, true, 1);
        // Keep the batch's own meters: `await_batch_done` clears the state copy.
        let meters = h
            .state
            .batch_progress
            .clone()
            .expect("the batch publishes its meters");
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        let load = |a: &AtomicU32| a.load(Ordering::Relaxed);
        assert_eq!(
            load(&meters.main.done),
            load(&meters.main.total),
            "every planned link settles: the dropped sibling is booked, not left hanging"
        );
    }

    /// The first real success on an endpoint retires its remaining links'
    /// real halves. Pipelining makes this best-effort: siblings whose fast
    /// halves settle together may start before the success lands, so the check
    /// sits AFTER the real permit (one slot here) — the saving is the links
    /// still waiting for capacity, which is the throughput-bound case the
    /// option exists for.
    #[tokio::test]
    async fn sibling_dedup_retires_links_waiting_behind_a_success() {
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        // dedup_endpoints=true (the default); one real slot makes the order
        // deterministic.
        let handle = start_test_batch_with(&mut h, plan, true, true, 1);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            1,
            "the sibling waiting for the real slot is retired by the success"
        );
        let links = &h.state.endpoints[0].links;
        let with_real = links.iter().filter(|l| l.latency.real_delay.is_some());
        assert_eq!(with_real.count(), 1, "exactly one link got a real result");
        for link in links {
            // The retired sibling never wrote a marker or a latency.
            assert!(link.error.is_none(), "retired link must not write a marker");
            assert_gate_clear(h.state.scheduler.as_ref(), link);
        }
    }

    #[tokio::test]
    async fn real_ping_test_all_protocols_tests_every_link() {
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        // real_ping_test_all_protocols=true → dedup off → both links tested.
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(h.runner.real_calls.load(Ordering::Relaxed), 2);
        for link in &h.state.endpoints[0].links {
            assert_eq!(
                link.latency,
                Latency {
                    real_delay: Some(50),
                    fast_delay: Some(10),
                    ip: Some("1.2.3.4".to_string()),
                    auth: None,
                }
            );
            assert!(link.error.is_none());
        }
    }

    /// The probe order is the WALK's order (`PageSort::Test` — the working
    /// servers first), and the merged pipeline keeps it (spec D15).
    ///
    /// Before the merge, the order came from the fast level: a link's real
    /// half started when its own fast half settled, so the probe order was the
    /// fast COMPLETION order. The merge removed the fast phase, so there is
    /// no completion order left to inherit — the walk's order IS the order,
    /// and the fast delays no longer steer it.
    ///
    /// The three rows are declared slowest-fastest by their fast delay, so
    /// the old pipeline would have probed them in the REVERSE order. The
    /// merged one probes them in the walk's order.
    #[tokio::test]
    async fn the_probes_follow_the_walk_order_not_the_fast_settle_order() {
        let rows = vec![
            fake_row(1, "10.0.0.1", 1),
            fake_row(2, "10.0.0.2", 1),
            fake_row(3, "10.0.0.3", 1),
        ];
        let mut h = harness(rows.clone()).await;
        {
            let mut delays = h.runner.fast_delay_by_addr.lock();
            delays.insert("10.0.0.1".to_string(), Duration::from_millis(150));
            delays.insert("10.0.0.2".to_string(), Duration::from_millis(50));
            delays.insert("10.0.0.3".to_string(), Duration::from_millis(100));
        }
        let plan = plan_from_rows(&rows);
        // One real slot: the semaphore is fair, so the recorded start order is
        // the dispatch order.
        let handle = start_test_batch_with(&mut h, plan, true, false, 1);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        let order = h.runner.real_endpoint_order.lock().clone();
        let expected: Vec<i64> = rows.iter().map(|r| r.endpoint.id.get()).collect::<Vec<_>>();
        assert_eq!(
            order, expected,
            "the probes follow the walk's order, not the retired fast settle order"
        );
    }

    // ── native testability gate ──────────────────────────────────────────
    #[tokio::test]
    async fn untestable_kind_is_marked_and_still_fast_probed() {
        let mut rows = vec![fake_row(1, "10.0.0.1", 1)];
        // A kind with no native implementation. The plan-time gate reads the
        // in-memory `proto_kind` only — the config is never loaded for it.
        for proto in rows[0].protocols.values_mut() {
            proto.proto_kind = leas_proto::proto_spec::ProtocolKind::Tuic;
        }
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        // Fast-only batch: the marker must still land (the gate runs for every
        // ping operation) and the fast probe must still run (R1).
        let handle = start_test_batch(&mut h, plan, false, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            1,
            "the fast probe still runs for an untestable row"
        );
        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            0,
            "no real probe for an untestable row"
        );
        // The marker lands AFTER the fast result: a fast success writes
        // `error = None`, so the reverse order would erase it.
        let link = &h.state.endpoints[0].links[0];
        let error = link.error.as_ref().expect("marker persisted");
        assert!(crate::ops::ping::is_untestable_marker(error), "{error:?}");
        assert!(error.text.contains("no native implementation"), "{error:?}");
    }

    #[test]
    fn untestable_markers_are_not_removable_failures() {
        let mut row = fake_row(1, "10.0.0.1", 1);
        let link = &mut row.links[0];
        link.error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: untestable_marker_text("no native implementation for this protocol kind"),
        });
        assert!(
            !is_removable_failure(link),
            "an untestable row must survive Remove Bad Servers"
        );
        link.error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "timeout".to_string(),
        });
        assert!(is_removable_failure(link), "a real failure still counts");
        link.error = None;
        assert!(!is_removable_failure(link));
    }

    // ── all-fail error markers ───────────────────────────────────────────

    #[tokio::test]
    async fn all_fail_writes_real_error_markers_on_every_link() {
        let rows = vec![fake_row(1, "10.0.0.1", 2), fake_row(2, "10.0.0.2", 1)];
        let mut h = harness(rows.clone()).await;
        *h.runner.real_outcome.lock() = ProbeOutcome::soft_failure("timeout");
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(h.runner.real_calls.load(Ordering::Relaxed), 3);
        for row in &h.state.endpoints {
            for link in &row.links {
                assert_eq!(
                    link.error.as_ref().map(|e| e.kind),
                    Some(ProfileErr::Real),
                    "every failing link persists a Real error marker: {link:?}"
                );
            }
        }
    }

    // ── DNS deferral ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn dns_deferred_links_are_retried_after_the_window() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let mut h = harness(rows.clone()).await;
        // Short window (2s): the batch must defer and then re-schedule. Two
        // seconds (not one) keeps the assertion robust to second-boundary
        // crossings: the batch always waits at least ~1s and at most ~2s.
        h.state.scheduler = Arc::new(TaskScheduler::new(3, 2));
        h.state.scheduler.mark_dns_failure(EndpointId::new(1));
        let plan = plan_from_rows(&rows);
        let started = std::time::Instant::now();
        let handle = start_test_batch(&mut h, plan, false, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            1,
            "the deferred link was eventually probed after the window"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "the retry must wait out the deferral window, took {:?}",
            started.elapsed()
        );
        assert!(matches!(
            h.state.endpoints[0].links[0].latency,
            Latency {
                fast_delay: Some(_),
                ..
            }
        ));
    }

    /// `dns_state_stamp` is the SIGNAL part 3 depends on: it must move when
    /// the endpoint's DNS state is re-armed, and hold still otherwise. That is
    /// the whole observable contract of the reset, and it can be tested
    /// directly — whereas driving it through `defer_retry` cannot discriminate,
    /// because the budget (`window + DNS_LOOKUP_TIMEOUT + 1s`) always exceeds
    /// the window by ~9 s, so the link is released at window expiry long before
    /// the budget could expire. See T9 in the plan: parts 1-3 are accepted
    /// STRUCTURALLY, and this is the test that carries what can be tested.
    #[tokio::test]
    async fn the_dns_state_stamp_moves_exactly_when_the_state_is_re_armed() {
        let sched = TaskScheduler::new(3, 2);
        let endpoint = EndpointId::new(7);
        assert_eq!(
            sched.dns_state_stamp(endpoint),
            None,
            "an endpoint with no DNS state carries no stamp",
        );

        // A failure opens a window.
        sched.mark_dns_failure(endpoint);
        let after_failure = sched.dns_state_stamp(endpoint);
        assert!(after_failure.is_some(), "a failure must produce a stamp");

        // An in-flight lookup is DNS state too, and overwrites it.
        //
        // The stamp is SECOND-granular, matching `is_dns_unresolved`'s own
        // arithmetic, so a re-arm inside the same second is invisible. That is
        // acceptable: the budget outlasts the window by ~9 s, so missing one
        // same-second re-arm cannot expire it. Cross the boundary explicitly
        // rather than asserting a move the granularity cannot express.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        sched.begin_dns_lookup(endpoint);
        assert_ne!(
            sched.dns_state_stamp(endpoint),
            after_failure,
            "starting a lookup must move the stamp once a second has passed",
        );
        sched.end_dns_lookup(endpoint);

        // The stamp holds STILL when nothing re-arms: a stable stamp is what
        // lets the budget keep counting instead of restarting every poll.
        let settled = sched.dns_state_stamp(endpoint);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            sched.dns_state_stamp(endpoint),
            settled,
            "an unchanged state must not move the stamp, or the budget would reset forever",
        );
    }

    /// The backoff must stay bounded: a flat short poll is ~60 gate
    /// acquisitions per deferred half, and 1,577 deferred halves made that
    /// ~95k spurious dispatches per batch — the contention this task removes.
    /// The schedule is 250 ms doubling to the window, so the FIRST poll is the
    /// bound on gate pressure before the doubling takes effect.
    #[test]
    fn the_deferral_poll_schedule_is_capped_at_the_window() {
        // Production sets `defer_delay` to the whole window; the loop must clamp
        // it, never sleep the window first.
        let window = Duration::from_secs(15);
        let mut backoff = window.min(DEFER_POLL_MIN).max(Duration::from_millis(1));
        assert_eq!(backoff, DEFER_POLL_MIN, "the first poll is clamped");
        // Walk the schedule and count acquisitions over one budget.
        let budget = window + Duration::from_secs(8) + Duration::from_secs(1);
        let mut waited = Duration::ZERO;
        let mut polls = 0usize;
        loop {
            waited = waited.saturating_add(backoff);
            polls += 1;
            backoff = (backoff.saturating_mul(2)).min(window);
            if waited >= budget {
                break;
            }
        }
        assert!(
            polls <= 10,
            "a doubling schedule capped at the window must stay near 6-8 polls, got {polls}",
        );
    }

    /// A DNS deferral is a `DnsDeferred` answer from `schedule`, which is
    /// returned BEFORE the gate is touched — so the deferred half holds no gate
    /// entry and only the retry task keeps it alive. `finish_batch` must wait for
    /// that retry (else the terminal event lands first, the retry's late result
    /// re-creates the meters, and the next batch is rejected as "already
    /// running").
    ///
    /// The marker lands inside this link's own fast probe, i.e. deterministically
    /// before its real half is scheduled: the deferral is therefore on the REAL
    /// half, which re-enters without ever touching the fast half again.
    #[tokio::test]
    async fn a_deferred_half_is_joined_before_finish_and_the_next_batch_starts() {
        let rows = vec![fake_row(1, "10.0.0.1", 1)];
        let mut h = harness(rows.clone()).await;
        h.state.scheduler = Arc::new(TaskScheduler::new(3, 3));
        *h.runner.dns_mark_on_real.lock() = Some((h.state.scheduler.clone(), EndpointId::new(1)));
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, true, false);
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        // The link got its result, no marker, and its gate is clear.
        //
        // The MERGED pipeline runs ONE probe per link (spec D1), so the DNS
        // marker — which the stub raises from the FAST probe — no longer has
        // a fast probe to land in. The deferral the test drives is therefore
        // raised from the REAL probe instead, which is the probe the merged
        // pipeline actually runs.
        assert_eq!(
            h.runner.real_calls.load(Ordering::Relaxed),
            1,
            "the deferred real half was probed after the window"
        );
        let link = &h.state.endpoints[0].links[0];
        assert!(link.latency.real_delay.is_some());
        assert!(link.error.is_none());
        assert_gate_clear(h.state.scheduler.as_ref(), link);
        assert!(
            h.state.batch_progress.is_none(),
            "meters must be cleared after the batch (terminal event last)"
        );

        // A subsequent batch starts cleanly. It is a FAST-ONLY batch, so the
        // TCP probe runs — and the counter now reads 1, because the merged
        // batch above ran no TCP probe at all.
        let plan2 = plan_from_rows(&rows);
        let handle2 = start_test_batch(&mut h, plan2, false, false);
        handle2.await.unwrap();
        await_batch_done(&mut h.state).await;
        assert_eq!(
            h.runner.fast_calls.load(Ordering::Relaxed),
            1,
            "the fast-only batch ran its one TCP probe"
        );
    }

    // ── stop mid-batch ───────────────────────────────────────────────────

    #[tokio::test]
    async fn stop_mid_batch_writes_no_error_markers() {
        let rows = vec![fake_row(1, "10.0.0.1", 2)];
        let mut h = harness(rows.clone()).await;
        let gate = Arc::new(Notify::new());
        *h.runner.real_gate.lock() = Some(gate.clone());
        let plan = plan_from_rows(&rows);
        // One real slot: the sibling's real half waits for capacity, so a stop
        // retires it without a probe.
        let handle = start_test_batch_with(&mut h, plan, true, false, 1);

        // Wait for the first real probe to be in flight, then stop.
        for _ in 0..300 {
            if h.runner.real_calls.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(h.runner.real_calls.load(Ordering::Relaxed) >= 1);
        h.state.speed_test_stop.store(true, Ordering::Relaxed);
        gate.notify_waiters();

        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        // No link carries an error marker; gates are clear.
        for link in &h.state.endpoints[0].links {
            assert!(
                link.error.is_none(),
                "stopped batch must not mark: {link:?}"
            );
            assert_gate_clear(h.state.scheduler.as_ref(), link);
        }
        // Only the in-flight probe ran; the sibling was retired without a probe.
        assert_eq!(h.runner.real_calls.load(Ordering::Relaxed), 1);
    }

    // ── meters and the terminal event ────────────────────────────────────

    /// The meters are two independent levels, so a numerator can never be read
    /// against another level's denominator (the 2026-09-16 run's bar paired
    /// phase-2 results with the whole 34,562-link plan). The real level's
    /// denominator is its own candidate set: the untestable and hard-failed
    /// links never enter it.
    #[tokio::test]
    async fn meters_track_both_levels_and_each_denominator_is_its_own() {
        let rows = vec![
            fake_row(1, "10.0.0.1", 1),
            fake_row(2, "10.0.0.2", 1),
            fake_row(3, "10.0.0.3", 1),
        ];
        let mut h = harness(rows.clone()).await;
        // Link 2's fast probe proves its proxy unreachable, so its real half is
        // skipped: 3 planned links, 2 real candidates.
        h.runner.fast_by_addr.lock().insert(
            "10.0.0.2".to_string(),
            ProbeOutcome::Failed {
                text: "IO: Connection refused (os error 111)".to_string(),
                class: ProbeClass::Refused,
                hard: true,
                transport_ms: None,
                evidence: None,
                // A refused socket: the transport never came up.
                transport_failed: true,
            },
        );
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch_with(&mut h, plan, true, false, 8);
        // Keep the batch's own meters: `await_batch_done` clears the state copy.
        let meters = h
            .state
            .batch_progress
            .clone()
            .expect("the batch publishes its meters");
        handle.await.unwrap();
        await_batch_done(&mut h.state).await;

        let load = |a: &AtomicU32| a.load(Ordering::Relaxed);
        // ONE level (spec D14): the merged pipeline's bar counts the planned
        // links, and the hard-failed one never becomes a real candidate — so
        // it is counted in the denominator but its real half never runs.
        assert_eq!(load(&meters.main.total), 3, "every planned link is counted");
        assert_eq!(load(&meters.main.done), 3);
        assert!(load(&meters.main.done) <= load(&meters.main.total));
    }

    /// The ETA needs a denominator, a rate sample and work left; anything else
    /// renders as `--` rather than a wrong estimate.
    #[test]
    fn phase_meters_eta_needs_a_denominator_a_rate_and_work_left() {
        let m = crate::types::PhaseMeters::default();
        assert_eq!(m.eta_secs(), None, "no denominator yet");
        m.total.store(100, Ordering::Relaxed);
        assert_eq!(m.eta_secs(), None, "no rate sample yet");
        m.rate_milli.store(2000, Ordering::Relaxed);
        assert_eq!(m.eta_secs(), Some(50), "100 left at 2/s");
        m.done.store(100, Ordering::Relaxed);
        assert_eq!(m.eta_secs(), None, "complete");
    }

    /// The plan line is the batch's own record of the walk (the store can drop
    /// it under a log flood, so the shape is pinned here rather than observed).
    #[test]
    fn plan_line_names_the_pages_links_and_walk_time() {
        assert_eq!(
            plan_line(56140, 136, 5446),
            "batch: planned 56140 link(s) over 136 page(s) in 5446 ms"
        );
        assert_eq!(
            plan_line(200, 1, 62),
            "batch: planned 200 link(s) over 1 page(s) in 62 ms"
        );
    }

    /// The rate window starts at the level's FIRST result, not at batch
    /// construction: otherwise the idle stretch before a level's first settle
    /// reads as ~0 results/s and pins that level's ETA at `--` (the 2026-09-17
    /// live run: 46 real results in 8 s, first sample 1 result over ~5 s → 0,
    /// and no later settle crossed a fresh second boundary).
    #[test]
    fn rate_window_starts_at_the_levels_first_result() {
        let meters = crate::types::PhaseMeters::default();
        meters.total.store(1000, Ordering::Relaxed);
        // A slot backdated as if the batch had been running for 5 idle seconds.
        let backdated = |secs: u64| {
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("backdate")
        };
        let slot = Mutex::new((backdated(5), 0));
        BatchShared::bump(&meters, &slot);
        assert_eq!(
            meters.rate_milli.load(Ordering::Relaxed),
            0,
            "one result is not a rate"
        );
        assert_eq!(meters.eta_secs(), None, "no estimate from a single result");

        // The next window has real activity: 1 s, one more result → 1/s.
        *slot.lock() = (backdated(1), 1);
        BatchShared::bump(&meters, &slot);
        assert_eq!(meters.rate_milli.load(Ordering::Relaxed), 1000);
        assert_eq!(meters.eta_secs(), Some(998), "998 left at 1/s");
    }

    /// One terminal event per batch, and no per-settle progress event: a
    /// feed-wide batch used to send ~34k of them, each describing state the
    /// shared meters already publish.
    #[tokio::test]
    async fn a_batch_emits_one_terminal_event_and_no_progress_events() {
        let rows = vec![
            fake_row(1, "10.0.0.1", 1),
            fake_row(2, "10.0.0.2", 1),
            fake_row(3, "10.0.0.3", 1),
        ];
        let mut h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let handle = start_test_batch(&mut h, plan, false, false);
        handle.await.unwrap();

        let mut rx = h.state.core_event_rx.take().expect("event receiver");
        let mut ended = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, CoreEvent::BatchEnded) {
                ended += 1;
            }
        }
        assert_eq!(ended, 1, "exactly one terminal event per batch");
    }

    /// The quit path reports an interrupted run with the summary a completed run
    /// writes. Before this, quitting mid-batch printed `3381 of 34562
    /// final-phase probe(s) reported, no batch summary` — the per-class
    /// histograms only `summary_line` renders died with the batch task (the
    /// runtime drop cancels it before `finish_batch`).
    #[tokio::test]
    async fn an_interrupted_run_renders_the_batch_summary() {
        let rows = vec![fake_row(1, "10.0.0.1", 1), fake_row(2, "10.0.0.2", 1)];
        let h = harness(rows.clone()).await;
        let plan = plan_from_rows(&rows);
        let params = build_params(&h, plan, true, false);
        let meters = params.meters.clone();
        let shared = BatchShared::new(params);
        shared.counters.real_ok.store(4, Ordering::Relaxed);
        shared.counters.real_failed.store(6, Ordering::Relaxed);
        meters.main.done.store(17, Ordering::Relaxed);
        shared.pending_real.store(2, Ordering::Relaxed);
        shared.pending_deferred.store(1, Ordering::Relaxed);
        bump_class(&shared.counters.real_fail, ProbeClass::Timeout);
        bump_class(&shared.counters.real_fail, ProbeClass::Timeout);
        bump_class(&shared.counters.real_fail, ProbeClass::Dns);

        let line = interrupted_summary_line(&shared);
        for expected in [
            "batch interrupted at quit:",
            "batch summary:",
            "real ok=4 failed=6 [timeout=2 dns=1]",
            "settled=17",
            "in-flight=3",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in: {line}");
        }
    }
}
