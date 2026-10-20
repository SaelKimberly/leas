use std::sync::Arc;
use std::sync::atomic::Ordering;

use leas_core::CoreType;
use leas_core::speed_test::TestType;
use leas_db::LinkGroups;
use leas_db::models::{
    EndpointId, EndpointRow, ErrorInfo, Latency, ProfileErr, ProfileStats, PurgeReason,
    TrafficStats,
};

use crate::AppState;
use crate::ops::profiles::endpoint_dns_unresolved;
use crate::types::{AppMode, CoreEvent, SettingsMode, SplitRightPane};

/// Format a profile ID as a URL-like hex identifier.
fn fmt_profile_id(id: i64) -> String {
    format!("leas://{id:x}")
}

/// Minimum spacing between result-driven Profiles page refetches while a batch
/// is running.
///
/// A refetch is one `profiles_page` + `load_page_projection` on the UI task
/// (measured 23 ms against a 16 ms tick on the 7,486-endpoint reference feed),
/// and a batch produces results continuously — unthrottled, the task that also
/// dispatches the probes spends the whole run reloading. A single (manual)
/// ping keeps its immediate refetch: it is one result, not a stream.
pub(crate) const RESULT_RELOAD_THROTTLE: std::time::Duration =
    std::time::Duration::from_millis(500);

/// Find the endpoint row whose links own `protocol_id` (a `Protocol` row id).
/// Endpoint ids (stable hashes of host:port) are unrelated to protocol ids,
/// so the match scans `r.links`.
#[must_use]
pub(crate) fn endpoint_row_for_protocol(
    endpoints: &mut [EndpointRow],
    protocol_id: i64,
) -> Option<&mut EndpointRow> {
    endpoints
        .iter_mut()
        .find(|r| r.links.iter().any(|l| l.protocol_id.get() == protocol_id))
}

/// True when `a` and `b` fall on the same civil day in the system local
/// time zone — the "today" boundary for the daily traffic reset.
/// Whether two epoch-second stamps fall on the same local day (the traffic
/// counters' daily reset).
fn same_local_day(a: i64, b: i64) -> bool {
    let tz = jiff::tz::TimeZone::system();
    let date = |secs: i64| {
        leas_db::models::from_epoch(secs)
            .to_zoned(tz.clone())
            .date()
    };
    date(a) == date(b)
}

/// True when `protocol_id` belongs to the currently connected endpoint — the
/// stale-event guard shared by the events handler and the disconnect flush:
/// only the connected session's poller may write traffic.
fn is_connected_protocol(state: &AppState, protocol_id: i64) -> bool {
    let Some(eid) = state.connected_protocol_id else {
        return false;
    };
    state.endpoints.iter().any(|row| {
        row.endpoint.id.get() == eid && row.links.iter().any(|l| l.protocol_id.get() == protocol_id)
    })
}

/// The persisted `error.kind` bucket for a test type: fast-class tests
/// (TCP/UDP) land in `Fast`, data-plane tests (real ping, speed) in `Real`.
/// Name-resolution failures surface on real attempts and share the real
/// bucket (the tier model already maps `Name` under real-err).
const fn err_kind_for(test_type: TestType) -> ProfileErr {
    match test_type {
        TestType::TcpPing | TestType::UdpTest => ProfileErr::Fast,
        TestType::RealPing | TestType::SpeedTest => ProfileErr::Real,
    }
}

/// Longest failure text a profile row will carry.
///
/// The debug per-result line prints the probe's full text — for a fast failure
/// that is the OS's own sentence, 238 characters of Russian on the 2026-09-27
/// Windows run — and `error_ttl_hours` defaults to never sweeping it, so a
/// column the UI renders as a three-character marker would hold a few hundred
/// bytes of prose per dead endpoint. The full text stays in the log; this is
/// the storage bound.
const MAX_ERROR_TEXT_CHARS: usize = 200;

/// Clamp a failure text to [`MAX_ERROR_TEXT_CHARS`] without losing the two
/// things a reader needs: the OS code, and the untestable marker's prefix.
fn cap_error_text(text: &str) -> String {
    // `is_untestable_marker` / `is_removable_failure` match on the PREFIX, and
    // a truncated marker would silently turn "never attempted by the native
    // engine" into an ordinary failure — one `remove_failed_servers` away from
    // deleting a row that was never tested. Never truncate one.
    if text.starts_with(crate::ops::ping::UNTESTABLE_PREFIX) {
        return text.to_owned();
    }
    if text.chars().count() <= MAX_ERROR_TEXT_CHARS {
        return text.to_owned();
    }
    // `(os error 10060)` is the only locale-independent token in a localized
    // OS sentence, and it sits at the END of it — so a plain prefix truncation
    // would keep 200 characters of Russian and drop the one part worth
    // searching for. Keep the head for context and re-attach the code, with the
    // head shortened so the TOTAL still fits the bound.
    // The suffix is built WITHOUT the ellipsis and pushed separately: slicing
    // it off the front by byte offset would split `…` (U+2026, three bytes)
    // and panic, on every long localized failure.
    let suffix = os_error_code(text).map_or_else(String::new, |code| format!("(os error {code})"));
    // One char of the budget is the ellipsis itself.
    let head_budget = MAX_ERROR_TEXT_CHARS
        .saturating_sub(suffix.chars().count())
        .saturating_sub(1);
    let mut kept: String = text.chars().take(head_budget).collect();
    kept.push('…');
    kept.push_str(&suffix);
    kept
}

/// The trailing `(os error N)` of an OS message, if it has one.
fn os_error_code(text: &str) -> Option<&str> {
    let start = text.rfind("(os error ")?;
    let rest = &text[start..];
    rest.strip_prefix("(os error ")?.strip_suffix(')')
}

/// Overlay one probe result onto `row`'s RESULT columns
/// (`latency*` / `speed_bps` / `error*`) and, when the probe decides it, the
/// PURGE column.
///
/// The single mapping behind both writers of a result: this module's handler
/// (which owns the in-memory page) and the batch's own writer staging in
/// `ops/ping.rs` (which must not depend on the page — a page reload mid-batch
/// used to drop every result whose row it no longer held, silently).
///
/// Returns the column groups the caller must stage, or `None` when nothing
/// changed. PURGE is included only when the verdict actually moved: it is the
/// classifier's own group (ADR 0002), so a fast probe's result cannot rewrite
/// it from a stale snapshot.
///
/// A `Cancelled` error never persists: a stopped test is not a failure (the
/// stop path emits `error: Some("Cancelled")` for sessions that never ran, and
/// a marker would paint `[fast]`/`[real]` on endpoints whose tests were merely
/// abandoned).
#[must_use]
pub(crate) fn apply_test_result(
    row: &mut ProfileStats,
    test_type: TestType,
    latency_ms: Option<u64>,
    speed_bps: Option<u64>,
    ip_info: Option<&str>,
    error: Option<&str>,
    purge: Option<PurgeReason>,
) -> Option<LinkGroups> {
    if let Some(err) = error {
        if err == "Cancelled" {
            return None;
        }
        // Persisted failure marker — the profiles Test column renders
        // `[fast]`/`[real]` from `link.error.kind`; the measurement (if any)
        // stays, so a dead host does not erase a previously measured delay.
        row.error = Some(ErrorInfo {
            kind: err_kind_for(test_type),
            text: cap_error_text(err),
        });
        // Only a real probe carries evidence; a fast result can never set a
        // verdict (a TCP handshake proves nothing about the config).
        if matches!(test_type, TestType::RealPing)
            && let Some(reason) = purge
        {
            row.purge_reason = Some(reason);
            return Some(LinkGroups::RESULT.union(LinkGroups::PURGE));
        }
        return Some(LinkGroups::RESULT);
    }
    match test_type {
        TestType::RealPing => {
            row.latency = latency_ms.map(|ms| Latency::Real {
                delay: ms as i32,
                ip: exit_ip(ip_info),
            });
        }
        TestType::TcpPing | TestType::UdpTest => {
            row.latency = latency_ms.map(|ms| Latency::Fast { delay: ms as i32 });
        }
        TestType::SpeedTest => row.speed_bps = speed_bps.map(|v| v as i64),
    }
    row.error = None;
    // A data-carrying success THROUGH the tunnel proves the config works: a
    // real probe built the tunnel from this link's own config, a speed test
    // carried bytes over it. A TCP handshake proves neither, so `TcpPing` and
    // `UdpTest` leave the verdict alone.
    if matches!(test_type, TestType::RealPing | TestType::SpeedTest) && row.purge_reason.is_some() {
        row.purge_reason = None;
        return Some(LinkGroups::RESULT.union(LinkGroups::PURGE));
    }
    Some(LinkGroups::RESULT)
}

/// The exit IP out of a probe's `"<ip> | <country>"` answer.
fn exit_ip(ip_info: Option<&str>) -> Option<String> {
    ip_info
        .and_then(|s| s.split('|').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Render a routing-engine event into an actions-log line.
///
/// Pure so the five variant renderings stay unit-testable without a channel
/// or an `AppState`. `timestamp_nanos` comes from the event's `jiff` timestamp
/// when the variant carries one (a nanosecond precision unix timestamp; the
/// engine emits at least second precision), falling back to zero for
/// `CompileWarning` which has no time field.
#[must_use]
pub fn render_route_event(ev: &leas_route::RouteEvent) -> crate::LogLine {
    use leas_route::events::RouteEvent as Re;
    let (msg, at) = match ev {
        Re::DecisionApplied {
            rule_name,
            tag,
            sni,
            at,
        } => (
            format!(
                "route: {} → {}{} ({at})",
                rule_name.as_deref().unwrap_or("<rule>"),
                tag.as_deref().unwrap_or("<default>"),
                sni.as_deref()
                    .map_or_else(String::new, |s| format!(" sni={s}"))
            ),
            *at,
        ),
        Re::Resolved { host, ips, at } => (format!("route: resolved {host} → {ips:?} ({at})"), *at),
        Re::NetworkBreakdown { failed_probe, at } => (
            format!("route: NETWORK BREAKDOWN probe {failed_probe} ({at})"),
            *at,
        ),
        Re::ProbeRecovered { probe, at } => (format!("route: probe recovered {probe} ({at})"), *at),
        Re::CompileWarning {
            rule_index,
            message,
        } => (
            format!("route: compile warning rule#{rule_index}: {message}"),
            jiff::Timestamp::UNIX_EPOCH,
        ),
    };
    crate::LogLine {
        level: "info".into(),
        target: "route".into(),
        message: msg,
        detail: None,
        timestamp_nanos: at.as_second() * 1_000_000_000 + i64::from(at.subsec_nanosecond()),
    }
}

/// Forward routing-engine events into the TUI core-event channel.
///
/// Mirrors the connect.rs stderr log pump: a recv loop converting each
/// `RouteEvent` into a `CoreEvent::Route`, dropped silently when the TUI is
/// gone (the receiver disconnect ends the loop). Nobody constructs an
/// [`leas_route::Engine`] in the TUI yet — the native-connect service
/// plugin will own the sender side; this is the receiving half.
pub fn spawn_route_event_forwarder(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<leas_route::RouteEvent>,
    core_event_tx: tokio::sync::mpsc::Sender<CoreEvent>,
) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            crate::try_send_or_warn(&core_event_tx, CoreEvent::Route(ev), "route_event");
        }
    });
}

/// Native traces applied per [`poll_core_events`] pass.
///
/// A connection storm queues traces faster than the UI draws, and the ring
/// only ever shows its newest rows, so a bounded slice per pass keeps the
/// event loop from starving rendering. Leftovers stay in the channel
/// (bounded, fed with `try_send`) and land on the next pass, which the
/// caller runs immediately because this one reports work handled.
const NATIVE_TRACE_BUDGET: usize = 512;

/// [`CoreEvent::EndpointInfoUpdated`] events processed per
/// [`poll_core_events`] call.
/// Enrichment passes emit one event per endpoint (10k+ at production scale);
/// without a cap one poll monopolizes the UI task and no draw or key event
/// is serviced until the whole backlog is drained. 256/16ms tick ≈ 16k
/// events/sec — a 10k flood clears in ~0.7s with renders interleaved.
const EVENT_DRAIN_BUDGET: usize = 256;

/// Poll core event channel and update state accordingly.
///
/// Returns `true` when anything was handled (an event consumed, or a finished
/// batch-progress bar cleared), so the caller can trigger an immediate redraw
/// instead of waiting for the idle refresh cadence.
pub async fn poll_core_events(state: &mut AppState) -> bool {
    // Clear meters left behind by a batch that never reported its end: the
    // handle published at batch start is the liveness fact (the meters
    // themselves cannot answer it — a running batch with no denominator yet is
    // a legitimate state), and the two clear together on the terminal event.
    let mut handled = if state.batch.is_none()
        && state.batch_progress.is_some()
        && state.testing_profiles.is_empty()
    {
        state.batch_progress = None;
        true
    } else {
        false
    };
    let mut trace_budget = NATIVE_TRACE_BUDGET;
    // Per-tick drain cap: enrichment passes can emit one event per endpoint
    // (10571+ at production scale). Draining the whole backlog in one poll
    // monopolizes the UI task and starves the render/key handling that only
    // runs between polls; a cap interleaves drain and draw every 16ms tick.
    let mut budget = EVENT_DRAIN_BUDGET;
    // DNS resolutions changed this pass, flushed as ONE spawned task after
    // the drain (see the `persist_batch.push` in the EndpointInfoUpdated arm).
    // `(endpoint, resolved IPs, epoch seconds of the lookup)`.
    let mut persist_batch: Vec<(EndpointId, Vec<std::net::IpAddr>, i64)> = Vec::new();
    while let Some(rx) = state.core_event_rx.as_mut() {
        let event = match rx.try_recv() {
            Ok(event) => event,
            Err(
                tokio::sync::mpsc::error::TryRecvError::Empty
                | tokio::sync::mpsc::error::TryRecvError::Disconnected,
            ) => break,
        };
        handled = true;
        match event {
            CoreEvent::Connected(core_type) => {
                // A native session starts from an empty ring: the session
                // task is aborted on teardown and can swallow its own
                // `Disconnected`, so the previous session's rows and totals
                // would otherwise linger into this one.
                if core_type == CoreType::Native {
                    state.reset_native_activity();
                }
                state.connected_core = Some(core_type);
                state.connecting = false;
                state.connection_error = None;
                state.log_trace("info", "core::process", &format!("Connected [{core_type}]"));
            }
            CoreEvent::Disconnected => {
                // Ignore stale Disconnected if already reconnecting
                if !state.connecting {
                    // Native session over: legs whose `Closed` trace died with
                    // the session task must not render live. Deliberately not
                    // gated on `connected_core`: `connect::disconnect` clears
                    // it synchronously, well before the session task emits
                    // this event, so a core-type guard would skip every
                    // user-initiated stop. The ring only ever holds native
                    // rows, and the call no-ops when none are open.
                    state.native_activity.close_out_open();
                    state.connected_core = None;
                    state.connected_protocol_id = None;
                    // Session over: the actions-log traffic segment must not
                    // keep showing the last session's deltas.
                    state.current_traffic_up = 0;
                    state.current_traffic_down = 0;
                    state.log_trace("info", "core::process", "Core process stopped");
                }
            }
            CoreEvent::Error(err) => {
                state.connection_error = Some(err.clone());
                state.connecting = false;
                state.connected_core = None;
                state.log_trace(
                    "error",
                    "core::process",
                    &format!("Connection error: {err}"),
                );
                state.connected_protocol_id = None;
            }
            CoreEvent::StatsError(msg) => {
                state.connection_error = Some(msg.clone());
                state.log_trace("warning", "core::process", &format!("Stats error: {msg}"));
            }
            CoreEvent::StatsUpdate {
                protocol_id,
                today_up,
                today_down,
                total_up,
                total_down,
            } => {
                state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TRAFFIC);
                state.connection_error = None;
                // Stale-event guard: only the connected session's poller may
                // write traffic. An event whose protocol the connected
                // endpoint does not own (left over from a profile switch, or
                // still in the channel after disconnect) must not accumulate
                // into the row or drive the actions-log deltas.
                if !is_connected_protocol(state, protocol_id) {
                    continue;
                }
                // protocol_id is a Protocol row id — match the row whose links
                // own it (never the endpoint id). Patch the link's traffic
                // in-memory and stage the traffic group (the gRPC stats poller
                // writes only these columns).
                let stats_writer = Arc::clone(&state.link_stage);
                if apply_stats_delta(
                    &mut state.endpoints,
                    protocol_id,
                    today_up,
                    today_down,
                    total_up,
                    total_down,
                ) && let Some(row) = endpoint_row_for_protocol(&mut state.endpoints, protocol_id)
                    && let Some(link) = row
                        .links
                        .iter_mut()
                        .find(|l| l.protocol_id.get() == protocol_id)
                {
                    // Only the traffic group: the stats poller must never
                    // rewrite latency/error from its snapshot.
                    stats_writer.stage(link, LinkGroups::TRAFFIC);
                }
                state.current_traffic_up = total_up;
                state.current_traffic_down = total_down;
            }
            CoreEvent::SysStatsUpdate(sys_stats) => {
                state.current_memory = sys_stats.alloc;
                state.system_stats = Some(sys_stats);
            }
            CoreEvent::LogLine { .. } => {}
            CoreEvent::NativeTrace(ev) => {
                state.record_native_trace(&ev);
                trace_budget = trace_budget.saturating_sub(1);
                if trace_budget == 0 {
                    break;
                }
            }
            CoreEvent::Route(ev) => {
                let line = render_route_event(&ev);
                state.log_cache.push_back(line);
                if state.log_cache.len() > 10_000 {
                    state.log_cache.pop_front();
                }
            }
            CoreEvent::TuiLog {
                target,
                level,
                message,
                detail,
                timestamp_nanos,
                persisted,
            } => {
                // The line is displayed here and is ALSO on its way to the heed
                // store, which the Logs tab polls. One watermark covers both
                // deliveries: advancing it here means the poll only reads what
                // this path never carried (a channel drop), instead of
                // re-delivering every info+ line a second time — which is what
                // the 2026-09-27 Windows dump shows, the same target and level
                // rendered twice for some lines and once for others.
                //
                // `persisted` is the guard that keeps this from losing instead
                // of duplicating: a session-only `log_activity` line has no
                // heed copy, so moving the watermark past it would step over
                // every unread info+ line behind it and the poll would never
                // deliver them. `max`, so a late arrival cannot pull it back.
                if persisted {
                    state.last_seen_log_ns =
                        state.last_seen_log_ns.max(timestamp_nanos.max(0) as u64);
                }
                state.log_cache.push_back(crate::LogLine {
                    level: level.to_lowercase(),
                    target,
                    message,
                    // The live line keeps its structured fields; the heed copy
                    // deliberately does not.
                    detail,
                    timestamp_nanos,
                });
                if state.log_cache.len() > 10_000 {
                    state.log_cache.pop_front();
                }
            }
            CoreEvent::ExportFinished { report, error } => {
                state.mode = crate::AppMode::List;
                if let Some(report) = report {
                    state.log_activity(
                        "info",
                        "tui::ops::export",
                        &format!(
                            "Exported {}: candidates={} emitted={} skipped={}",
                            report.scope.title(),
                            report.candidate_count,
                            report.emitted_count,
                            report.skipped_count
                        ),
                    );
                } else if let Some(error) = error {
                    state.log_activity("error", "tui::ops::export", &error);
                }
            }
            CoreEvent::SubscriptionsUpdated {
                group_id,
                count,
                error,
                summary,
            } => {
                state.updating_groups.remove(&group_id);
                if summary.total_errors > 0 || summary.security_warning_count > 0 {
                    let mut msg = format!(
                        "Subscription validation: {} error(s) (missing fields: {}, host validation: {}, other: {}), {} warning(s) (profiles with insecure=true)",
                        summary.total_errors,
                        summary.missing_field_count,
                        summary.host_validation_count,
                        summary.other_count,
                        summary.security_warning_count,
                    );
                    // WHY, not just how many. The counters alone left the
                    // 2026-10-01 run's `1 links, 1 errors` subscription
                    // undiagnosable — it failed 4/4 with every bucket zero
                    // except `other`, and the reason was discarded at the parse
                    // site. Bounded: a 90k-link feed must not become a wall.
                    if !summary.sample_errors.is_empty() {
                        msg.push_str(" — first reasons: ");
                        msg.push_str(&summary.sample_errors.join("; "));
                        if summary.sample_errors_omitted > 0 {
                            use std::fmt::Write as _;
                            let _ = write!(msg, " (+{} more)", summary.sample_errors_omitted);
                        }
                    }
                    state.log_trace("warn", "tui::ops::subscriptions", &msg);
                }
                if let Some(err) = error {
                    state.log_trace(
                        "error",
                        "tui::ops::subscriptions",
                        &format!("Subscription update failed: {err}"),
                    );
                } else {
                    state.log_trace(
                        "info",
                        "tui::ops::subscriptions",
                        &format!("Subscription updated: {count} profiles"),
                    );
                }
                // Reload OFF the UI task: a whole-table read at 10k+ endpoints
                // takes seconds — awaiting it inline here froze input/render
                // after every subscription update. The load runs in the
                // background and the rows arrive via `ProfilesRowsReady`
                // (generation-guarded so a slower load never clobbers a newer
                // one). Groups are tiny — reload those inline.
                let db = state.db.clone();
                let load = crate::ops::profiles::ProfilesLoad::from(&*state);
                let generation = state.reload_gen.wrapping_add(1);
                state.reload_gen = generation;
                let tx = state.core_event_tx.clone();
                tokio::spawn(async move {
                    match crate::ops::profiles::load_profiles_rows(&db, &load).await {
                        Ok((rows, meta)) => {
                            if let Some(t) = &tx {
                                crate::try_send_or_warn(
                                    t,
                                    CoreEvent::ProfilesRowsReady {
                                        generation,
                                        rows,
                                        meta,
                                    },
                                    "profiles_ready",
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "tui::ops::events",
                                "profile rows load failed: {e}"
                            );
                        }
                    }
                });
                state.reload_groups().await;
            }
            CoreEvent::ProfilesRowsReady {
                generation,
                rows,
                meta,
            } => {
                if generation == state.reload_gen {
                    crate::ops::profiles::apply_profiles_rows(state, rows, &meta);
                }
                // A newer reload superseded this one — drop the stale rows.
            }
            CoreEvent::RetentionPurged { count } => {
                state.log_trace(
                    "info",
                    "tui::ops::events",
                    &format!("Retention reclaimed {count} profile(s)"),
                );
                // The loaded page may have lost rows: re-read it on this tick.
                state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
                state.filter_cache_valid.set(false);
            }
            CoreEvent::CompactFinished { merged, text } => {
                state.log_trace("info", "tui::ops::compact", &text);
                state.maint_progress = None;
                if merged != 0 {
                    // Merges delete endpoints: the loaded page must be re-read.
                    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
                    state.filter_cache_valid.set(false);
                }
            }
            CoreEvent::DnsRetryTargets { targets } => {
                let count = targets.len();
                for (endpoint_id, host, sni) in targets {
                    crate::ops::enrich::spawn_dns_resolve_host(
                        state,
                        endpoint_id,
                        host,
                        leas_db::models::HostType::Dns,
                        sni,
                        crate::ops::enrich::ResolveTrigger::Maintenance,
                    );
                }
                state.log_trace(
                    "info",
                    "tui::ops::compact",
                    &format!("DNS retry: {count} endpoint(s) dispatched"),
                );
            }
            CoreEvent::MaintenanceDone => {
                state.log_trace("info", "tui::ops::compact", "DNS retry: complete");
                state.maint_progress = None;
                crate::ops::enrich::set_resolve_progress(None);
            }
            CoreEvent::TestTypeUpdate {
                endpoint_id,
                protocol_id,
                test_type,
            } => {
                state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);
                state
                    .testing_details
                    .insert((endpoint_id, protocol_id), test_type);
                state.testing_profiles.insert((endpoint_id, protocol_id));
            }
            CoreEvent::SpeedTestResult {
                endpoint_id,
                protocol_id,
                test_type,
                latency_ms,
                speed_bps,
                ip_info,
                error,
                purge,
            } => {
                // The test result mutates link latency/speed/error and the
                // testing_details map — the profiles display cache must
                // rebuild the affected rows.
                state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TEST);
                // Guard against duplicate events for the same (endpoint,
                // protocol) pair — the unique ProfileStats row. Protocol-only
                // keys dropped the second result when two endpoints shared a
                // `Protocol` row (identity dedup excludes host/port), leaving
                // the probed endpoint's link empty.
                if !state.testing_profiles.remove(&(endpoint_id, protocol_id)) {
                    // Already processed — skip
                    continue;
                }
                state.testing_details.remove(&(endpoint_id, protocol_id));

                // Capture endpoint context before the mutable row borrow below.
                // Resolution is by the event's endpoint id — the row that
                // actually ran the probe — never by first protocol owner.
                let (ep_id, ep_host_is_dns) = state
                    .endpoints
                    .iter()
                    .find(|r| r.endpoint.id.get() == endpoint_id)
                    .map_or((0, false), |r| (r.endpoint.id.get(), r.endpoint.is_dns()));
                let ip_info_clone = ip_info.clone();
                let writer = Arc::clone(&state.link_stage);

                let mut on_page = true;
                let name = {
                    let row = state
                        .endpoints
                        .iter_mut()
                        .find(|r| r.endpoint.id.get() == endpoint_id);
                    if let Some(row) = row {
                        if let Some(link) = row
                            .links
                            .iter_mut()
                            .find(|l| l.protocol_id.get() == protocol_id)
                        {
                            // Staged, not committed: the flush task batches
                            // it off the UI task. A stopped test returns `None`
                            // and stages nothing, and the returned groups carry
                            // PURGE only when the verdict moved.
                            let is_real = test_type == TestType::RealPing;
                            let sample = is_real
                                && state.batch_progress.is_none()
                                && !error.as_deref().is_some_and(|e| {
                                    e.starts_with(crate::ops::ping::UNTESTABLE_PREFIX)
                                });
                            if let Some(groups) = apply_test_result(
                                link,
                                test_type,
                                latency_ms,
                                speed_bps,
                                ip_info.as_deref(),
                                error.as_deref(),
                                purge,
                            ) {
                                // STABILITY, single pings only. A batch stages
                                // its own samples (its rows are off-page here),
                                // so sampling in both would count every batch
                                // probe twice. `batch_progress` is published
                                // before the batch's first probe and cleared at
                                // its end: a single ping for one link can only
                                // MISS a sample here, never double one.
                                if sample {
                                    let ok = error.is_none();
                                    let (mask, len) = leas_db::endpoint_rank::append_sample(
                                        link.stab_mask.cast_unsigned(),
                                        u8::try_from(link.stab_len.clamp(
                                            0,
                                            i64::from(leas_db::endpoint_rank::STAB_WINDOW),
                                        ))
                                        .unwrap_or(0),
                                        ok,
                                    );
                                    link.stab_mask = mask.cast_signed();
                                    link.stab_len = i64::from(len);
                                    writer.stage(link, groups.union(LinkGroups::STAB));
                                } else {
                                    writer.stage(link, groups);
                                }
                            }
                        }
                    } else {
                        // The page does not hold this row: the batch stages its
                        // own results, so this is a UI-only miss (a page reload
                        // while a batch runs). Never silent.
                        on_page = false;
                        tracing::debug!(
                            target: "tui::ops::events",
                            endpoint_id,
                            protocol_id,
                            "result for a row outside the loaded page: UI row not updated"
                        );
                    }
                    fmt_profile_id(protocol_id)
                };

                if let Some(err) = &error {
                    // Per-result lines are data, not diagnostics: the failure
                    // TEXT is already persisted on the link (`profile_stats.
                    // error_text`, the Test column's marker) and the batch's
                    // summary carries the per-class counts. A 31k-link run
                    // wrote 15,934 of these in 16 minutes (2026-09-16), so they
                    // reach the actions panel only, never the log store.
                    state.log_activity(
                        "debug",
                        "tui::ops::speedtest",
                        &format!("{test_type:?} failed for {name}: {err}"),
                    );
                } else {
                    let latency_str = latency_ms.map(|ms| format!("{ms}ms")).unwrap_or_default();
                    let speed_str = speed_bps.map(|bps| format!("{bps}bps")).unwrap_or_default();
                    let detail = if !speed_str.is_empty() {
                        speed_str
                    } else if !latency_str.is_empty() {
                        latency_str
                    } else {
                        "success".to_string()
                    };
                    // Success is the same per-result chatter (one line per link
                    // made a 5-minute batch produce 32k log lines on
                    // 2026-09-15): actions panel only.
                    state.log_activity(
                        "debug",
                        "tui::ops::speedtest",
                        &format!("{test_type:?} {name}: {detail}"),
                    );
                }

                // Live sub-table ordering: re-sort the endpoint's links by test
                // priority after every fast/real ping result. `selected_sub`
                // follows its protocol to its new index (only when this
                // result's endpoint is the one currently selected).
                if on_page && matches!(test_type, TestType::TcpPing | TestType::RealPing) {
                    let keep = if state.selected_profile_id() == Some(ep_id) {
                        state.selected_sub.and_then(|n| {
                            state
                                .endpoints
                                .iter()
                                .find(|r| r.endpoint.id.get() == ep_id)
                                .and_then(|r| r.links.get(n).map(|l| l.protocol_id))
                        })
                    } else {
                        None
                    };
                    let dns_unresolved = state
                        .endpoints
                        .iter()
                        .find(|r| r.endpoint.id.get() == ep_id)
                        .is_some_and(|r| endpoint_dns_unresolved(state, r));
                    if let Some(row) = state
                        .endpoints
                        .iter_mut()
                        .find(|r| r.endpoint.id.get() == ep_id)
                    {
                        row.sort_links_by_test_priority(dns_unresolved);
                        if let Some(pid) = keep {
                            state.selected_sub =
                                row.links.iter().position(|l| l.protocol_id == pid);
                        }
                        // Single-row display follows the best MEASURED link
                        // (real-ok lowest delay, else fast-ok lowest) after
                        // every fast/real result, success or failure — the
                        // sort's implicit best-first order is test-priority
                        // (fresh failures dominate, untested above errors),
                        // which is the right sub-table order but the wrong
                        // display choice: a link with a measured success must
                        // drive the row. A pinned manual override wins via
                        // `active_link()` (checked first).
                        row.select_best_measured_link();
                    }
                    // Page refetch policy. The row above was already patched in
                    // memory, so the refetch exists only to re-place it in the
                    // ordered WINDOW — which is a fact about a row this page can
                    // show. Two guards keep a running batch off the UI task:
                    //
                    // - off-page results (a feed-wide batch's ~98%: the window
                    //   holds 200 of the feed) have nothing to re-place here;
                    // - while a batch is live, at most one refetch per
                    //   `RESULT_RELOAD_THROTTLE`.
                    //
                    // Measured cost of the unconditional version: one
                    // `profiles_page` + hydrate per 16 ms tick (23 ms on the
                    // 7,486-endpoint reference feed) for the whole run, on the
                    // same task that dispatches the probes.
                    let now = std::time::Instant::now();
                    let due = state.batch_progress.is_none()
                        || state
                            .last_result_reload
                            .get()
                            .is_none_or(|last| now.duration_since(last) >= RESULT_RELOAD_THROTTLE);
                    if due {
                        state.last_result_reload.set(Some(now));
                        state.filter_cache_valid.set(false);
                    }
                }

                // Update tracking fields for actions log
                match test_type {
                    TestType::TcpPing => state.last_test_tcp = latency_ms,
                    TestType::RealPing => state.last_test_real = latency_ms,
                    TestType::SpeedTest => state.last_test_speed = speed_bps,
                    TestType::UdpTest => {} // no tracking for UDP
                }

                // Auto-reset stop flag when all tests complete. While a batch
                // is active (`batch_progress` set) the flag must survive the
                // phase-1 → phase-2 transition even if every fast result
                // drained `testing_profiles` — the batch task clears the
                // progress itself and re-arms the flag when it ends.
                if state.testing_profiles.is_empty() && state.batch_progress.is_none() {
                    state.speed_test_stop.store(false, Ordering::Relaxed);
                    // The last SINGLE (non-batch) test has settled. A batch
                    // flushes at `finish_batch`, and a manual ping stages 1-3
                    // column groups — far below the timer floor — so nothing
                    // would write it before `max_staged_age` (15 s). The Test
                    // cell already shows the result (patched in memory), so the
                    // lag is invisible until a reload or restart.
                    //
                    // WAKE, do not flush: `draining_results_performs_no_commit_
                    // on_the_ui_task` is a standing guard that draining a result
                    // must not commit on the UI task. The background loop's
                    // size-trigger arm always writes, so waking it gets the
                    // latency without the commit. The `batch_progress` guard
                    // keeps this out of the batch path, where T3's coalescing is
                    // the point.
                    state.link_stage.flush_soon();
                }

                // Real ping happened — record the exit IP + country on the
                // endpoint; DNS-host endpoints get their inbound resolved too
                // (deferred-resolution trigger: real networking occurred).
                if ip_info_clone.is_some() {
                    crate::ops::enrich::spawn_outbound_enrich(state, ep_id, ip_info_clone);
                }
                if ep_host_is_dns {
                    crate::ops::enrich::spawn_dns_resolve(state, ep_id, false);
                }
            }
            CoreEvent::UpdateCheckResult {
                core_type,
                current_version,
                latest_version,
                error,
            } => {
                let status = state.update_status.entry(core_type).or_default();
                status.current_version.clone_from(&current_version);
                status.latest_version.clone_from(&latest_version);
                status.update_available = current_version.as_ref().map_or_else(
                    // Not installed but latest known → install available
                    || latest_version.is_some(),
                    |cur_str| {
                        latest_version.as_ref().is_some_and(|latest_str| {
                            let cur = leas_core::updater::parse_version(cur_str);
                            let latest = leas_core::updater::parse_version(latest_str);
                            match (cur, latest) {
                                (Some(c), Some(l)) => leas_core::updater::is_newer(&c, &l),
                                _ => false,
                            }
                        })
                    },
                );
                status.error = error;
                if let Some(ref ver) = latest_version {
                    match core_type {
                        CoreType::Xray => {
                            state.config.updates.xray_latest_known = Some(ver.clone());
                        }
                        CoreType::SingBox => {
                            state.config.updates.sing_box_latest_known = Some(ver.clone());
                        }
                        // Native is in-process: no binary, no version check.
                        CoreType::Auto | CoreType::Native => {}
                    }
                }
                // Refresh form snapshots if currently viewing the updates form
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right:
                                SplitRightPane::UpdateForm {
                                    status_xray,
                                    status_singbox,
                                },
                            ..
                        },
                } = &mut state.mode
                {
                    *status_xray = state
                        .update_status
                        .get(&CoreType::Xray)
                        .cloned()
                        .unwrap_or_default();
                    *status_singbox = state
                        .update_status
                        .get(&CoreType::SingBox)
                        .cloned()
                        .unwrap_or_default();
                }
            }
            CoreEvent::UpdateDownloadProgress {
                core_type,
                downloaded,
                total,
            } => {
                if let Some(status) = state.update_status.get_mut(&core_type) {
                    status.download_progress = Some((downloaded, total));
                }
            }
            CoreEvent::UpdateCompleted {
                core_type,
                old_version,
                new_version,
                success,
                error,
            } => {
                let status = state.update_status.entry(core_type).or_default();
                status.downloading = false;
                status.download_progress = None;
                if success {
                    status.current_version = Some(new_version.clone());
                    status.update_available = false;
                    state.log_trace(
                        "info",
                        "tui::ops::events",
                        &format!(
                            "{core_type} updated: {} → {}",
                            old_version.as_deref().unwrap_or("none"),
                            new_version,
                        ),
                    );
                } else {
                    status.error.clone_from(&error);
                    state.log_trace(
                        "error",
                        "tui::ops::events",
                        &format!("{core_type} update failed: {error:?}"),
                    );
                }
                // Refresh form snapshots if currently viewing the updates form
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right:
                                SplitRightPane::UpdateForm {
                                    status_xray,
                                    status_singbox,
                                },
                            ..
                        },
                } = &mut state.mode
                {
                    *status_xray = state
                        .update_status
                        .get(&CoreType::Xray)
                        .cloned()
                        .unwrap_or_default();
                    *status_singbox = state
                        .update_status
                        .get(&CoreType::SingBox)
                        .cloned()
                        .unwrap_or_default();
                }
            }
            CoreEvent::BatchEnded => {
                // Batch finished: clear the shared meters and re-arm the stop
                // flag (the pipeline retired everything; a stopped batch must not
                // leave the status bar stuck). The handle goes with them —
                // `finish_batch` is the batch's only end signal, and it flushes
                // and sweeps before sending this.
                state.batch_progress = None;
                state.batch = None;
                state.speed_test_stop.store(false, Ordering::Relaxed);
                // The run's last results may have been throttled (the page
                // refetch during a batch is at most one per
                // `RESULT_RELOAD_THROTTLE`), so settle the window on the exact
                // final order — this is also the first tick after which no
                // further result will re-place a row.
                state.last_result_reload.set(None);
                state.filter_cache_valid.set(false);
            }
            CoreEvent::HostFeaturesLoaded(checker) => {
                state.host_features = Some(checker);
                state.log_trace("info", "tui::state", "Whitelist loaded");
                // Refresh whitelist features for every endpoint (never
                // persisted — cached entries must track the current files).
                crate::ops::enrich::spawn_whitelist_pass(state);
            }
            CoreEvent::EndpointInfoUpdated { endpoint_id, info } => {
                // The merge mutates endpoint_info (resolved IPs, country,
                // outbound) — the profiles display cache must rebuild.
                state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_COUNTRY);
                // Before the merge: was this endpoint's DNS unresolved?
                let was_resolved = state
                    .endpoint_info
                    .get(&endpoint_id)
                    .is_some_and(|i| !i.resolved_ips.is_empty());
                // Merge by field group so concurrent enrichment (resolution /
                // whitelist / outbound) does not clobber each other. An event
                // with an empty `resolved_ips` may materialize an entry — a
                // failed lookup, or an outbound-only event that knows the exit
                // IP but not the inbound address. Such an entry is safe: it
                // reads as "no address and no attempt", which both
                // `should_resolve` and the startup seeding pass treat as "still
                // needs resolving" rather than as a resolved IP host.
                let mut persist: Option<(Vec<std::net::IpAddr>, i64)> = None;
                if !info.resolved_ips.is_empty()
                    || info.sni_whitelisted.is_some()
                    || info.outbound_ip.is_some()
                    || info.resolved_at_secs.is_some()
                {
                    let entry = state.endpoint_info.entry(endpoint_id).or_default();
                    if !info.resolved_ips.is_empty() {
                        let had_resolved_at = entry.resolved_at_secs;
                        entry.resolved_ips = info.resolved_ips;
                        entry.resolved_at_secs = info.resolved_at_secs;
                        // country is derived (mmdb) — a lookup failure in a
                        // re-resolution returns None; keep the known value
                        // rather than clearing it.
                        entry.country = info.country.or_else(|| entry.country.clone());
                        // Keep the current flags when the incoming event
                        // carries defaults (seed pass before whitelist load).
                        entry.host_features =
                            merge_host_features(entry.host_features, info.host_features);
                        // Persist only when the resolution itself changed
                        // (whitelist-pass copies carry the same timestamp and
                        // must not re-write).
                        if entry.resolved_at_secs.is_some()
                            && had_resolved_at != entry.resolved_at_secs
                        {
                            // The addresses go to the database as they are:
                            // `endpoint_ip` stores the packed address, so
                            // nothing renders text on the write path.
                            persist = Some((
                                entry.resolved_ips.clone(),
                                entry.resolved_at_secs.unwrap_or(0),
                            ));
                        }
                    } else if info.resolved_at_secs.is_some() {
                        // Failed lookup (empty result): record the attempt so
                        // re-resolution is TTL-gated instead of re-running on
                        // every trigger. `x` (force) still re-attempts.
                        entry.resolved_at_secs = info.resolved_at_secs;
                    }
                    if info.sni_whitelisted.is_some() {
                        entry.sni_whitelisted = info.sni_whitelisted;
                    }
                    if info.outbound_ip.is_some() {
                        entry.outbound_ip = info.outbound_ip;
                        entry.outbound_country = info.outbound_country;
                    }
                }
                // Persist DNS resolutions (DNS hosts only) so launches don't
                // re-resolve; the TTL gate applies across restarts.
                if let Some((resolved_ips, resolved_at)) = persist {
                    // Batched: one spawned flush per poll instead of one
                    // task per event — an enrichment flood must not create
                    // thousands of concurrent DB write tasks.
                    persist_batch.push((EndpointId::new(endpoint_id), resolved_ips, resolved_at));
                }

                // DNS flip (unresolved -> resolved): lift the endpoint's
                // protocols out of the name (bottom) tier.
                let is_resolved = state
                    .endpoint_info
                    .get(&endpoint_id)
                    .is_some_and(|i| !i.resolved_ips.is_empty());
                if !was_resolved && is_resolved {
                    if let Some(row) = state
                        .endpoints
                        .iter_mut()
                        .find(|r| r.endpoint.id.get() == endpoint_id)
                    {
                        row.sort_links_by_test_priority(false);
                    }
                    state.filter_cache_valid.set(false);
                }
            }
            CoreEvent::DnsResolveRequest {
                endpoint_id,
                host,
                host_type,
                sni,
            } => {
                // The batch plans every endpoint in the feed but the UI holds
                // only the loaded page, so it carries the endpoint facts with
                // the request rather than an id to look up. Resolving by id here
                // is what left every off-page DNS host `[name]` for good.
                crate::ops::enrich::spawn_dns_resolve_host(
                    state,
                    endpoint_id,
                    host,
                    host_type,
                    sni,
                    crate::ops::enrich::ResolveTrigger::Routine,
                );
            }
        }
        budget -= 1;
        if budget == 0 {
            // Cap reached: stop for this tick so a draw and key handling
            // interleave; the next poll resumes the drain. `break` (not
            // return) so the post-loop tail still runs.
            break;
        }
    }
    // Flush this pass's DNS-resolution writes as ONE spawned task: an
    // enrichment flood previously spawned one DB task per event.
    if !persist_batch.is_empty() {
        let db = state.db.clone();
        tokio::spawn(async move {
            for (eid, resolved_ips, resolved_at) in persist_batch {
                // The address set (`endpoint_ip`) + `resolved_at` are the
                // ONLY owner of a DNS endpoint's resolutions.
                if let Err(e) = db
                    .update_endpoint_resolution(eid, resolved_ips, resolved_at)
                    .await
                {
                    tracing::warn!(
                        target: "tui::ops::events",
                        "update_endpoint_resolution failed: {e}"
                    );
                }
            }
        });
    }
    handled
}

/// Merge whitelist feature flags from an `EndpointInfoUpdated` event into the
/// cached entry, guarding against a seed phase-2 event clobbering real values.
///
/// `spawn_dns_resolve` captures the whitelist checker at spawn time; on first
/// launch it is `None`, so the seed event carries `HostFeatures::default()`.
/// If that event lands after the whitelist pass, its default flags would wipe
/// the real ones for the session — keep the current value in that case.
#[must_use]
pub(crate) fn merge_host_features(
    current: leas_host_features::HostFeatures,
    incoming: leas_host_features::HostFeatures,
) -> leas_host_features::HostFeatures {
    if incoming == leas_host_features::HostFeatures::default() {
        current
    } else {
        incoming
    }
}

/// Accumulate one poller delta into the owning link's traffic counters.
///
/// The poller reports deltas since the last poll (`query_stats(..., reset =
/// true)` for xray; one `/traffic` line per second for sing-box). The "today"
/// counters reset when the row's last-write day differs from today (jiff
/// civil-date comparison) — totals never reset. The row day boundary is the
/// row's `updated_at`, refreshed here so consecutive same-day writes
/// accumulate. Persistence stays with the caller: the T21 event handler
/// persists every event, and the disconnect flush persists once after
/// draining.
fn apply_stats_delta(
    endpoints: &mut [EndpointRow],
    protocol_id: i64,
    today_up: i64,
    today_down: i64,
    total_up: i64,
    total_down: i64,
) -> bool {
    let Some(row) = endpoint_row_for_protocol(endpoints, protocol_id) else {
        return false;
    };
    let Some(link) = row
        .links
        .iter_mut()
        .find(|l| l.protocol_id.get() == protocol_id)
    else {
        return false;
    };
    let now = leas_db::models::now_epoch();
    let (base_up, base_down) = if same_local_day(link.updated_at, now) {
        (link.traffic.today_up, link.traffic.today_down)
    } else {
        (0, 0)
    };
    link.traffic = TrafficStats {
        today_up: base_up + today_up,
        today_down: base_down + today_down,
        total_up: link.traffic.total_up + total_up,
        total_down: link.traffic.total_down + total_down,
    };
    link.updated_at = now;
    true
}

/// Drain the core-event channel of `StatsUpdate` events the poller sent
/// before disconnect — the event loop (which drains once per frame) may not
/// have processed them yet, so the final session delta could otherwise be
/// lost when the task is aborted. Only deltas belonging to the connected
/// session are accumulated (the same guard as the events handler); returns
/// the final row state of every touched link for the caller to persist.
///
/// Non-stats events are NOT dropped: they are buffered and re-sent through
/// the channel so the event loop still delivers them after disconnect — a
/// pending `SubscriptionsUpdated`/`SpeedTestResult`/`EndpointInfoUpdated`
/// must not be lost (e.g. a `SubscriptionsUpdated` whose
/// `updating_groups.remove` never runs would leave the group spinner stuck).
/// Session-scoped lifecycle/error events (`Connected`/`Disconnected`/
/// `Error`/`StatsError`) are exceptions: meaningless after teardown, and
/// their handlers mutate session state unconditionally — a re-sent
/// `StatsError` would re-set `connection_error` after `disconnect()` cleared
/// it (the footer would paint "Error: ..." for the whole disconnected
/// period), and a re-sent `Connected` would resurrect `connected_core` on a
/// disconnected UI.
pub(crate) fn drain_pending_stats_updates(state: &mut AppState) -> Vec<ProfileStats> {
    let mut touched: Vec<ProfileStats> = Vec::new();
    let mut non_stats: Vec<CoreEvent> = Vec::new();
    while let Some(rx) = state.core_event_rx.as_mut() {
        let Ok(event) = rx.try_recv() else {
            break;
        };
        match event {
            CoreEvent::StatsUpdate {
                protocol_id,
                today_up,
                today_down,
                total_up,
                total_down,
            } => {
                state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_TRAFFIC);
                if !is_connected_protocol(state, protocol_id) {
                    continue;
                }
                if apply_stats_delta(
                    &mut state.endpoints,
                    protocol_id,
                    today_up,
                    today_down,
                    total_up,
                    total_down,
                ) && let Some(link) =
                    endpoint_row_for_protocol(&mut state.endpoints, protocol_id).and_then(|row| {
                        row.links
                            .iter()
                            .find(|l| l.protocol_id.get() == protocol_id)
                    })
                {
                    // Keep only the final state per link (a protocol can
                    // appear more than once if several ticks were pending).
                    touched.retain(|l| l.protocol_id != link.protocol_id);
                    touched.push(link.clone());
                }
            }
            // Session-scoped: dropped at the disconnect boundary.
            CoreEvent::Connected(_)
            | CoreEvent::Disconnected
            | CoreEvent::Error(_)
            | CoreEvent::StatsError(_) => {}
            other => non_stats.push(other),
        }
    }
    // Re-send non-stats events in drain order (channel capacity is 65536 in
    // production; a drop here is bounded by a full queue, not by the drain).
    if let Some(tx) = &state.core_event_tx {
        for event in non_stats {
            let _ = tx.try_send(event);
        }
    }
    touched
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use leas_config::AppConfig;
    use leas_db::models::{EndpointRow, Latency};

    use crate::ops::profiles::test_support::fake_row;
    use crate::types::EndpointInfo;

    use super::*;

    /// A stored failure text is bounded, and the bound is on CHARACTERS — the
    /// sentence that needed it in the first place was Russian, and a byte
    /// bound on multi-byte text cuts mid-codepoint.
    #[test]
    fn stored_failure_text_is_bounded_on_a_char_boundary() {
        let short = "IO: timed out (os error 10060)";
        assert_eq!(cap_error_text(short), short, "a short text is untouched");

        // The exact shape that motivated the cap: an OS sentence far past the
        // bound, in a non-ASCII locale.
        let long: String = "Попытка установить соединение была безуспешной. ".repeat(20);
        let capped = cap_error_text(&long);
        assert_eq!(capped.chars().count(), MAX_ERROR_TEXT_CHARS);
        assert!(capped.ends_with('…'), "truncation is marked");
        // Round-trips: no replacement char, no panic on a char boundary.
        assert!(!capped.contains('\u{fffd}'));
    }

    /// The OS code is the one locale-independent token in a localized sentence,
    /// and it sits at the END — a plain prefix truncation would keep 200
    /// characters of Russian and drop the only part worth searching for.
    #[test]
    fn a_capped_failure_text_keeps_its_os_code() {
        let long: String =
            "Попытка установить соединение была безуспешной. ".repeat(20) + " (os error 10060)";
        let capped = cap_error_text(&long);
        assert!(
            capped.ends_with("(os error 10060)"),
            "code survives truncation: {capped:?}"
        );
        assert!(capped.contains('…'), "truncation is still marked");
        assert_eq!(
            capped.chars().count(),
            MAX_ERROR_TEXT_CHARS,
            "the code is re-attached INSIDE the bound, not on top of it"
        );
    }

    /// `is_untestable_marker` and `is_removable_failure` match on the PREFIX.
    /// A truncated marker would silently reclassify "never attempted by the
    /// native engine" as an ordinary failure — one `remove_failed_servers`
    /// away from deleting a row that was never tested.
    #[test]
    fn an_untestable_marker_is_never_truncated() {
        let marker = crate::ops::ping::untestable_marker_text(
            "a deliberately long reason that would otherwise be cut off by the cap, \
             padded out to well past the two hundred character storage bound \
             with more words appended to it here",
        );
        assert!(
            marker.chars().count() > MAX_ERROR_TEXT_CHARS,
            "the fixture must exceed the bound for this to test anything"
        );
        let capped = cap_error_text(&marker);
        assert_eq!(capped, marker, "an untestable marker is stored verbatim");
        assert!(capped.starts_with(crate::ops::ping::UNTESTABLE_PREFIX));
        assert!(crate::ops::ping::is_untestable_marker(
            &leas_db::models::ErrorInfo {
                kind: leas_db::models::ProfileErr::Real,
                text: capped,
            }
        ));
    }

    /// The verdict rule, which is the whole point of the PURGE group: only a
    /// REAL probe can move it, and only a data-carrying success can clear it.
    #[test]
    fn only_a_real_probe_moves_the_purge_verdict() {
        let mut link = fake_row(1, "h.example", 1).links.remove(0);
        assert_eq!(link.purge_reason, None);

        // A fast failure — even one the caller handed a verdict — sets
        // LATENCY/ERROR only. (The batch never supplies one for a fast probe;
        // this pins the guard rather than the caller's discipline.)
        let groups = apply_test_result(
            &mut link,
            TestType::TcpPing,
            None,
            None,
            None,
            Some("timeout after 5s"),
            Some(PurgeReason::TransportRejected),
        )
        .expect("changed");
        assert_eq!(
            groups,
            LinkGroups::RESULT,
            "no PURGE group for a fast probe"
        );
        assert_eq!(link.purge_reason, None, "a TCP handshake proves nothing");

        // A real failure with evidence earns the verdict, in its own group.
        let groups = apply_test_result(
            &mut link,
            TestType::RealPing,
            None,
            None,
            None,
            Some("REALITY error: received real certificate"),
            Some(PurgeReason::RealityFallback),
        )
        .expect("changed");
        assert!(groups.contains(LinkGroups::PURGE), "the verdict moved");
        assert_eq!(link.purge_reason, Some(PurgeReason::RealityFallback));

        // A real failure WITHOUT evidence (a timeout) leaves it alone.
        let groups = apply_test_result(
            &mut link,
            TestType::RealPing,
            None,
            None,
            None,
            Some("timeout on probe attempt (limit 5s)"),
            None,
        )
        .expect("changed");
        assert!(!groups.contains(LinkGroups::PURGE));
        assert_eq!(link.purge_reason, Some(PurgeReason::RealityFallback));

        // A fast SUCCESS must not clear it either.
        let _ = apply_test_result(
            &mut link,
            TestType::TcpPing,
            Some(42),
            None,
            None,
            None,
            None,
        );
        assert_eq!(link.purge_reason, Some(PurgeReason::RealityFallback));

        // A real success clears it, and says so.
        let groups = apply_test_result(
            &mut link,
            TestType::RealPing,
            Some(120),
            None,
            Some("198.51.100.9 | DE"),
            None,
            None,
        )
        .expect("changed");
        assert!(groups.contains(LinkGroups::PURGE), "the verdict moved back");
        assert_eq!(link.purge_reason, None);

        // And a Cancelled result is not a result at all.
        link.purge_reason = Some(PurgeReason::NotTls);
        assert_eq!(
            apply_test_result(
                &mut link,
                TestType::RealPing,
                None,
                None,
                None,
                Some("Cancelled"),
                None,
            ),
            None,
            "a stopped test stages nothing"
        );
        assert_eq!(link.purge_reason, Some(PurgeReason::NotTls));
    }

    /// A speed test rides an established tunnel, so its success is a
    /// data-carrying proof too — it clears a verdict, and its own failures
    /// (which carry no evidence) never set one.
    #[test]
    fn a_speed_test_success_also_clears_the_verdict() {
        let mut link = fake_row(1, "h.example", 1).links.remove(0);
        link.purge_reason = Some(PurgeReason::OriginUnreachable);

        let groups = apply_test_result(
            &mut link,
            TestType::SpeedTest,
            None,
            Some(9_000_000),
            None,
            None,
            None,
        )
        .expect("changed");
        assert!(groups.contains(LinkGroups::PURGE));
        assert_eq!(link.purge_reason, None);

        let groups = apply_test_result(
            &mut link,
            TestType::SpeedTest,
            None,
            None,
            None,
            Some("Connection refused"),
            None,
        )
        .expect("changed");
        assert!(
            !groups.contains(LinkGroups::PURGE),
            "no evidence, no verdict"
        );
        assert_eq!(link.purge_reason, None);
    }

    /// Multi-protocol endpoint fixture. Protocol ids `[start..start+n]`.
    fn row_with_protocols(endpoint_id: i64, n: usize, start: i64) -> EndpointRow {
        let mut row = fake_row(endpoint_id, &format!("h{endpoint_id}.example"), n);
        // Rebase the link protocol ids onto `start` so tests control the ids.
        for (i, link) in row.links.iter_mut().enumerate() {
            let new_pid = start + i as i64;
            let protocol = row
                .protocols
                .remove(&link.protocol_id)
                .unwrap_or_else(|| crate::ops::profiles::leas_db_helper::vless_protocol(new_pid));
            link.protocol_id = leas_db::models::ProtocolId::new(new_pid);
            row.protocols.insert(link.protocol_id, protocol);
        }
        row
    }

    /// Pre-set a link's latency (fast or real) before a result event lands.
    fn set_delay(row: &mut EndpointRow, pid: i64, delay: i32, real: bool) {
        let link = row
            .links
            .iter_mut()
            .find(|l| l.protocol_id.get() == pid)
            .expect("link exists");
        link.latency = if real {
            Some(Latency::Real { delay, ip: None })
        } else {
            Some(Latency::Fast { delay })
        };
    }

    fn empty_page_meta() -> leas_db::profiles_query::PageMeta {
        leas_db::profiles_query::PageMeta {
            ids: Vec::new(),
            total: 0,
            offset: 0,
        }
    }

    async fn event_state() -> (AppState, tokio::sync::mpsc::Sender<CoreEvent>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, AppConfig::default()).await;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        (state, tx)
    }

    /// A `TraceEvent::Opened` carrying the fields the activity ring reads.
    fn opened(conn_id: u64) -> leas_native::telemetry::TraceEvent {
        use leas_native::telemetry::{TraceEvent, TraceKind, TraceOpened, TraceSecurity};
        TraceEvent::Opened(TraceOpened {
            conn_id,
            kind: TraceKind::Tcp,
            dest: format!("h{conn_id}.example:443").into(),
            protocol: "vless".into(),
            transport: "tcp".into(),
            security: TraceSecurity::Tls,
        })
    }

    /// The matching `TraceEvent::Closed` (100 up / 200 down, no error).
    fn closed(conn_id: u64) -> leas_native::telemetry::TraceEvent {
        use leas_native::telemetry::{TraceClosed, TraceEvent};
        TraceEvent::Closed(TraceClosed {
            conn_id,
            up_bytes: 100,
            down_bytes: 200,
            duration_ms: 5,
            error: None,
        })
    }

    #[tokio::test]
    async fn native_session_resets_the_ring_and_closes_out_open_rows() {
        let (mut state, tx) = event_state().await;

        // Session one: two legs open, one of them closes.
        tx.send(CoreEvent::Connected(CoreType::Native))
            .await
            .unwrap();
        tx.send(CoreEvent::NativeTrace(opened(1))).await.unwrap();
        tx.send(CoreEvent::NativeTrace(opened(2))).await.unwrap();
        tx.send(CoreEvent::NativeTrace(closed(1))).await.unwrap();
        assert!(poll_core_events(&mut state).await);
        assert_eq!(state.native_activity.entries.len(), 2);
        assert_eq!(state.native_activity.open_count, 1);

        // Disconnect: leg 2 never reported a close (its trace died with the
        // session task) — it must still end up closed, count at 0. Mimic the
        // real user-initiated order: `connect::disconnect` clears
        // `connected_core` synchronously and the session task emits
        // `Disconnected` afterwards, so the close-out must not depend on the
        // core still being set.
        state.connected_core = None;
        tx.send(CoreEvent::Disconnected).await.unwrap();
        poll_core_events(&mut state).await;
        assert_eq!(state.native_activity.open_count, 0);
        assert!(state.native_activity.entries.iter().all(|e| e.closed));
        assert_eq!(state.native_activity.total_up, 100);

        // Session two starts empty: no rows, no totals from session one.
        tx.send(CoreEvent::Connected(CoreType::Native))
            .await
            .unwrap();
        poll_core_events(&mut state).await;
        assert!(state.native_activity.entries.is_empty());
        assert_eq!(
            (
                state.native_activity.total_up,
                state.native_activity.total_down,
                state.native_activity.open_count,
                state.native_activity.fail_count,
            ),
            (0, 0, 0, 0)
        );

        // Connecting a subprocess core leaves the native ring alone.
        tx.send(CoreEvent::NativeTrace(opened(3))).await.unwrap();
        tx.send(CoreEvent::Connected(CoreType::Xray)).await.unwrap();
        poll_core_events(&mut state).await;
        assert_eq!(state.native_activity.entries.len(), 1);
    }

    #[tokio::test]
    async fn native_trace_drain_stops_at_the_per_pass_budget() {
        let (mut state, _unused) = event_state().await;
        // Wider channel than the fixture's: the storm must fit in the queue.
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        state.core_event_rx = Some(rx);

        let over = NATIVE_TRACE_BUDGET + 40;
        for i in 0..over {
            tx.send(CoreEvent::NativeTrace(opened(i as u64)))
                .await
                .unwrap();
        }
        assert!(poll_core_events(&mut state).await);
        // One pass applies at most the per-pass budget AND the global drain
        // cap (whichever is smaller — the drain cap governs) and leaves the
        // rest queued so the frame can draw.
        let first = state.native_activity.entries.len();
        assert_eq!(first, NATIVE_TRACE_BUDGET.min(EVENT_DRAIN_BUDGET));
        // Successive passes resume where the last stopped — nothing is lost.
        while state.native_activity.entries.len() < over {
            poll_core_events(&mut state).await;
        }
        assert_eq!(state.native_activity.entries.len(), over);
    }

    #[test]
    fn merge_host_features_keeps_existing_when_incoming_is_default() {
        let real = leas_host_features::HostFeatures {
            sni_whitelisted: true,
            ip_whitelisted: true,
            cidr_whitelisted: false,
        };
        // A seed phase-2 event carries `HostFeatures::default()` when the
        // whitelist checker was not loaded at spawn; it must not clobber the
        // flags a later whitelist pass already applied.
        assert_eq!(
            merge_host_features(real, leas_host_features::HostFeatures::default()),
            real
        );
        // A genuine whitelist-pass event still overwrites with real values.
        let other = leas_host_features::HostFeatures {
            sni_whitelisted: false,
            ip_whitelisted: false,
            cidr_whitelisted: true,
        };
        assert_eq!(merge_host_features(real, other), other);
    }

    /// The result-driven page refetch is per-VISIBLE-row, and at most one per
    /// `RESULT_RELOAD_THROTTLE` while a batch runs.
    ///
    /// A refetch is a full `profiles_page` + `load_page_projection` on the UI
    /// task (measured 23 ms against a 16 ms tick on the 7,486-endpoint
    /// reference feed), and a feed-wide batch's results are ~98% off-page: the
    /// window holds 200 of the feed. Unconditional invalidation kept that task
    /// reloading for the whole run.
    #[tokio::test]
    async fn result_driven_page_reload_is_visible_row_and_throttled() {
        use crate::ops::profiles::test_support::{fake_row, test_state};

        /// Queue one armed result pair (the `TestTypeUpdate` re-arms the
        /// handler's dedupe guard) and drain it.
        async fn armed_result(
            state: &mut AppState,
            tx: &tokio::sync::mpsc::Sender<CoreEvent>,
            pair: (i64, i64),
        ) {
            tx.try_send(CoreEvent::TestTypeUpdate {
                endpoint_id: pair.0,
                protocol_id: pair.1,
                test_type: TestType::TcpPing,
            })
            .expect("arm");
            tx.try_send(CoreEvent::SpeedTestResult {
                endpoint_id: pair.0,
                protocol_id: pair.1,
                test_type: TestType::TcpPing,
                latency_ms: Some(7),
                speed_bps: None,
                ip_info: None,
                error: None,
                purge: None,
            })
            .expect("result");
            let _ = state.poll_core_events().await;
        }

        let rows = vec![fake_row(1, "10.0.0.1", 3), fake_row(2, "10.0.0.2", 3)];
        let on_page = (
            rows[0].endpoint.id.get(),
            rows[0].links[0].protocol_id.get(),
        );
        let on_page_2 = (
            rows[0].endpoint.id.get(),
            rows[0].links[1].protocol_id.get(),
        );
        let off_page = (9_999, 999_901);
        let mut state = test_state(rows).await;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        state.core_event_tx = Some(tx.clone());
        state.core_event_rx = Some(rx);

        // Off-page: nothing to re-place in this window, no refetch.
        state.filter_cache_valid.set(true);
        armed_result(&mut state, &tx, off_page).await;
        assert!(
            state.filter_cache_valid.get(),
            "an off-page result must not refetch the page"
        );

        // On-page, no batch: the row moves at once (one manual ping is not a
        // stream).
        state.filter_cache_valid.set(true);
        armed_result(&mut state, &tx, on_page).await;
        assert!(
            !state.filter_cache_valid.get(),
            "a visible result refetches immediately outside a batch"
        );

        // On-page during a batch: the first one refetches, the second inside
        // the throttle window does not. Both halves of the batch handle are
        // set: `poll_core_events` treats a progress meter with no published
        // handle as a batch that never reported its end and clears it.
        state.batch_progress = Some(Arc::new(crate::types::BatchMeters::default()));
        state.batch = Some(Arc::new(std::sync::OnceLock::new()));
        state.last_result_reload.set(None);
        state.filter_cache_valid.set(true);
        armed_result(&mut state, &tx, on_page).await;
        assert!(
            !state.filter_cache_valid.get(),
            "the first result of the window still refetches"
        );
        state.filter_cache_valid.set(true);
        armed_result(&mut state, &tx, on_page_2).await;
        assert!(
            state.filter_cache_valid.get(),
            "a second visible result inside the throttle window must not"
        );

        // The batch's end settles the window on the final order.
        tx.try_send(CoreEvent::BatchEnded).expect("end");
        state.filter_cache_valid.set(true);
        let _ = state.poll_core_events().await;
        assert!(
            !state.filter_cache_valid.get(),
            "BatchEnded forces the last refetch the throttle may have skipped"
        );
        assert!(state.last_result_reload.get().is_none(), "stamp reset");
    }

    #[tokio::test]
    async fn poll_core_events_reports_whether_events_were_handled() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, AppConfig::default()).await;
        // Isolate from the startup channels (whitelist load, auto-update):
        // replace the rx so only this test can feed events — deterministic.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        // Idle: no events -> false (keeps the refresh-cadence draw path).
        assert!(!state.poll_core_events().await);
        // A real event -> true, and the state change is applied.
        tx.send(CoreEvent::Connected(CoreType::Xray)).await.unwrap();
        assert!(state.poll_core_events().await);
        assert_eq!(state.connected_core, Some(CoreType::Xray));
        // Drained -> idle again.
        assert!(!state.poll_core_events().await);
    }

    /// The retention pass runs off the event loop, so its result has to come
    /// back through the channel: the handler must invalidate the loaded page
    /// (it may just have lost rows) and say so in the log.
    #[tokio::test]
    async fn retention_purge_invalidates_the_loaded_page() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, AppConfig::default()).await;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.filter_cache_valid.set(true);
        let gen_before = state.endpoints_gen;

        tx.send(CoreEvent::RetentionPurged { count: 2 })
            .await
            .unwrap();
        assert!(state.poll_core_events().await);
        assert!(
            !state.filter_cache_valid.get(),
            "the next tick must re-read the page"
        );
        assert_ne!(
            state.endpoints_gen, gen_before,
            "the display cache's key must move with the dataset"
        );
    }

    #[test]
    fn endpoint_row_for_protocol_matches_protocol_id_not_endpoint_id() {
        // endpoint id 100 has link protocol 7; endpoint id 101 has link 9
        let mut rows = vec![row_with_protocols(100, 1, 7), row_with_protocols(101, 1, 9)];

        assert_eq!(
            endpoint_row_for_protocol(&mut rows, 9).map(|r| r.endpoint.id.get()),
            Some(101)
        );
        assert_eq!(
            endpoint_row_for_protocol(&mut rows, 7).map(|r| r.endpoint.id.get()),
            Some(100)
        );
        // Endpoint ids are not protocol ids — the lookup must not match them.
        assert!(endpoint_row_for_protocol(&mut rows, 100).is_none());
        assert!(endpoint_row_for_protocol(&mut rows, 999).is_none());
    }

    /// The batch's whole point: draining a tick's worth of results performs NO
    /// database commit on the UI task. Everything is staged; the flush task
    /// owns the transaction.
    #[tokio::test]
    async fn draining_results_performs_no_commit_on_the_ui_task() {
        let (mut state, tx) = event_state().await;
        let row = row_with_protocols(100, 1, 7);
        let link = row.links[0].clone();
        state.endpoints = vec![row];
        state.connected_protocol_id = Some(100);
        let _ = state.db.upsert_link(&link).await;
        state.endpoints[0].links[0].latency = None;

        // Send and drain in lockstep: the channel holds 16, and the point is
        // that each drained result stages instead of committing.
        for i in 0..256u64 {
            state.testing_profiles.insert((100, 7));
            tx.send(CoreEvent::SpeedTestResult {
                endpoint_id: 100,
                protocol_id: 7,
                test_type: TestType::TcpPing,
                latency_ms: Some(10 + i),
                speed_bps: None,
                ip_info: None,
                error: None,
                purge: None,
            })
            .await
            .expect("send");
            let _ = state.poll_core_events().await;
        }

        assert_eq!(
            state.link_stage.flush_count(),
            0,
            "a drain tick must not commit anything on the UI task"
        );
        assert!(
            state.link_stage.staged_len() > 0,
            "the result is staged for the flush task"
        );

        // The flush task (here: an explicit flush) is what writes it.
        state.link_stage.flush().await.expect("flush");
        assert_eq!(state.link_stage.flush_count(), 1, "one transaction");
    }

    #[tokio::test]
    async fn stats_update_resets_today_on_day_change_and_keeps_totals() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 1, 7); // one link, protocol 7
        let link = &mut row.links[0];
        link.traffic = TrafficStats {
            today_up: 100,
            today_down: 200,
            total_up: 1_000,
            total_down: 2_000,
        };
        // Last write 48h ago — a different civil day in any time zone.
        let now = jiff::Timestamp::now();
        link.updated_at = now.as_second() - 48 * 3600;
        state.endpoints = vec![row];
        // The events handler only accepts traffic from the connected session
        // (T22 stale-event guard): the connected endpoint owns protocol 7.
        state.connected_protocol_id = Some(100);

        // Day changed: today counters reset before the delta is added,
        // totals keep accumulating.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 5,
            today_down: 10,
            total_up: 5,
            total_down: 10,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        let link = &state.endpoints[0].links[0];
        assert_eq!(link.traffic.today_up, 5, "today_up reset on day change");
        assert_eq!(
            link.traffic.today_down, 10,
            "today_down reset on day change"
        );
        assert_eq!(link.traffic.total_up, 1_005, "total_up keeps accumulating");
        assert_eq!(
            link.traffic.total_down, 2_010,
            "total_down keeps accumulating"
        );

        // Same day: the next delta accumulates on top of today's counters.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 3,
            today_down: 4,
            total_up: 3,
            total_down: 4,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        let link = &state.endpoints[0].links[0];
        assert_eq!(link.traffic.today_up, 8, "same-day write accumulates");
        assert_eq!(link.traffic.today_down, 14);
        assert_eq!(link.traffic.total_up, 1_008);
        assert_eq!(link.traffic.total_down, 2_014);

        // The accumulated row is STAGED, not committed on the UI task: flush
        // the write-behind writer, then re-read.
        state.link_stage.flush().await.expect("flush");
        let mut conn = state.db.connection().await.unwrap();
        let stored = leas_db::models::ProfileStats::filter_by_protocol_id_and_endpoint_id(
            leas_db::models::ProtocolId::new(7),
            leas_db::models::EndpointId::new(100),
        )
        .first()
        .exec(&mut conn)
        .await
        .unwrap()
        .expect("link persisted");
        assert_eq!(stored.traffic.today_up, 8);
        assert_eq!(stored.traffic.total_up, 1_008);
    }

    #[tokio::test]
    async fn stats_update_after_disconnect_is_ignored() {
        let (mut state, tx) = event_state().await;
        let row = row_with_protocols(100, 1, 7); // one link, protocol 7
        state.endpoints = vec![row];
        state.connected_protocol_id = Some(100);

        // A session delta lands while connected: accumulated + drives the
        // actions-log segment.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 100,
            today_down: 200,
            total_up: 100,
            total_down: 200,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert_eq!(state.endpoints[0].links[0].traffic.total_up, 100);
        assert_eq!(state.current_traffic_up, 100);

        // Disconnect clears the session state (also exercised by the
        // connect.rs disconnect test — the drain here finds no pending
        // events, so nothing is flushed).
        state.disconnect();
        assert_eq!(state.connected_protocol_id, None);
        assert_eq!(state.current_traffic_up, 0);

        // A stale event arriving post-disconnect is ignored: it must not
        // accumulate into the row (double-count) nor drive the actions-log
        // deltas.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 50,
            today_down: 60,
            total_up: 50,
            total_down: 60,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        let link = &state.endpoints[0].links[0];
        assert_eq!(
            link.traffic.total_up, 100,
            "stale delta must not accumulate after disconnect"
        );
        assert_eq!(
            link.traffic.total_down, 200,
            "stale delta must not accumulate after disconnect"
        );
        assert_eq!(
            state.current_traffic_up, 0,
            "stale delta must not drive the actions log"
        );
        assert_eq!(state.current_traffic_down, 0);

        // Same guard applies to a profile-switch: traffic for a protocol the
        // connected endpoint does not own is ignored even while connected.
        state.connected_protocol_id = Some(100);
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 999, // owned by no endpoint row
            today_up: 5,
            today_down: 5,
            total_up: 5,
            total_down: 5,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert_eq!(state.endpoints[0].links[0].traffic.total_up, 100);
        assert_eq!(state.current_traffic_up, 0);
    }

    #[tokio::test]
    async fn profiles_rows_ready_applies_only_current_generation() {
        let (mut state, tx) = event_state().await;
        state.core_event_tx = Some(tx.clone());
        let row = row_with_protocols(100, 1, 7);
        state.reload_gen = 5;

        // Stale load (generation 4 < 5): dropped, endpoints untouched.
        tx.send(CoreEvent::ProfilesRowsReady {
            generation: 4,
            rows: vec![row.clone()],
            meta: empty_page_meta(),
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert!(state.endpoints.is_empty(), "stale rows must be dropped");

        // Current generation: applied.
        tx.send(CoreEvent::ProfilesRowsReady {
            generation: 5,
            rows: vec![row],
            meta: empty_page_meta(),
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert_eq!(state.endpoints.len(), 1, "matching rows applied");
    }

    #[tokio::test]
    async fn drain_flush_preserves_non_stats_events() {
        // The disconnect flush must not eat non-stats events: a pending
        // SubscriptionsUpdated that is dropped would leave updating_groups
        // stuck (spinner forever). Use an aligned channel pair — the drain
        // re-sends through `core_event_tx`, so send + rx must share it.
        let (mut state, _orig_tx) = event_state().await;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.core_event_tx = Some(tx.clone());
        let row = row_with_protocols(100, 1, 7);
        state.endpoints = vec![row];
        state.connected_protocol_id = Some(100);
        // A group update is in flight when disconnect happens.
        state.updating_groups.insert("g1".to_string());

        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 5,
            today_down: 10,
            total_up: 5,
            total_down: 10,
        })
        .await
        .unwrap();
        tx.send(CoreEvent::SubscriptionsUpdated {
            group_id: "g1".to_string(),
            count: 3,
            error: None,
            summary: leas_config::import_export::ValidationSummary::default(),
        })
        .await
        .unwrap();

        // Disconnect flush: the stats delta is accumulated...
        let flushed = super::drain_pending_stats_updates(&mut state);
        assert_eq!(flushed.len(), 1, "stats delta flushed");
        assert_eq!(state.endpoints[0].links[0].traffic.total_up, 5);
        // ... and the non-stats event was re-sent: the event loop still
        // delivers it (the handler clears the in-flight group).
        assert!(state.poll_core_events().await);
        assert!(
            !state.updating_groups.contains("g1"),
            "subscription result delivered post-drain"
        );
    }

    #[tokio::test]
    async fn drain_flush_drops_session_scoped_error_events() {
        // Session-scoped lifecycle/error events pending at disconnect must
        // not be re-sent: a re-sent StatsError would re-set
        // `connection_error` after disconnect() cleared it (stale "Error:"
        // footer), and a re-sent Connected would resurrect connected_core on
        // a disconnected UI.
        let (mut state, _orig_tx) = event_state().await;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.core_event_tx = Some(tx.clone());
        let row = row_with_protocols(100, 1, 7);
        state.endpoints = vec![row];
        state.connected_protocol_id = Some(100);
        state.connected_core = Some(CoreType::Xray);

        tx.send(CoreEvent::StatsError("stats api unavailable".to_string()))
            .await
            .unwrap();
        tx.send(CoreEvent::Error("config build failed".to_string()))
            .await
            .unwrap();
        tx.send(CoreEvent::Connected(CoreType::Xray)).await.unwrap();

        state.disconnect();
        assert_eq!(
            state.connection_error, None,
            "footer stays clean after disconnect"
        );
        assert_eq!(
            state.connected_core, None,
            "connected state not resurrected by a stale Connected"
        );
        // The only event re-delivered after the drain is disconnect()'s own
        // "Disconnected" TuiLog (it logs through the same channel) — the
        // session-scoped StatsError/Error/Connected must be gone.
        let mut seen_disconnect_log = false;
        while let Some(rx) = state.core_event_rx.as_mut() {
            match rx.try_recv() {
                Ok(CoreEvent::TuiLog { message, .. }) => {
                    seen_disconnect_log |= message.contains("Disconnected");
                }
                Ok(other) => panic!("unexpected re-sent event after disconnect: {other:?}"),
                Err(_) => break,
            }
        }
        assert!(seen_disconnect_log, "disconnect log present");
    }

    #[tokio::test]
    async fn drain_flush_guards_connected_session_and_flushes_all_links() {
        let (mut state, _orig_tx) = event_state().await;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.core_event_tx = Some(tx.clone());
        // Endpoint 100 owns protocols 7 + 8; endpoint 200 owns protocol 9.
        let row = row_with_protocols(100, 2, 7);
        let other = row_with_protocols(200, 1, 9);
        state.endpoints = vec![row, other];
        state.connected_protocol_id = Some(100);

        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 7,
            today_up: 10,
            today_down: 20,
            total_up: 10,
            total_down: 20,
        })
        .await
        .unwrap();
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 8,
            today_up: 30,
            today_down: 40,
            total_up: 30,
            total_down: 40,
        })
        .await
        .unwrap();
        // A foreign session's tick (endpoint 200) must be rejected by the
        // same guard the events handler applies.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 9,
            today_up: 99,
            today_down: 99,
            total_up: 99,
            total_down: 99,
        })
        .await
        .unwrap();

        let flushed = super::drain_pending_stats_updates(&mut state);
        // Every owned link touched by the drain is returned for persistence.
        let mut pids: Vec<i64> = flushed.iter().map(|l| l.protocol_id.get()).collect();
        pids.sort_unstable();
        assert_eq!(pids, vec![7, 8], "both owned links flushed");
        let p7 = state.endpoints[0]
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 7)
            .unwrap();
        assert_eq!(p7.traffic.total_up, 10);
        let p8 = state.endpoints[0]
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 8)
            .unwrap();
        assert_eq!(p8.traffic.total_up, 30);
        let p9 = state.endpoints[1]
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 9)
            .unwrap();
        assert_eq!(p9.traffic.total_up, 0, "foreign-session delta rejected");
    }

    #[tokio::test]
    async fn shared_protocol_result_writes_to_probing_endpoint_only() {
        // Two endpoints share the same `Protocol` row (identity dedup
        // excludes host/port): a ping on endpoint 2's link used to land on
        // endpoint 1's row — the handler resolved by protocol id with
        // `.find()` (first owner) and the per-protocol dedupe guard dropped
        // the second endpoint's result as a "duplicate". Both must work per
        // (endpoint, protocol) pair.
        let (mut state, tx) = event_state().await;
        let mut ep1 = fake_row(1, "1.1.1.1", 2); // p100, p101
        let mut ep2 = fake_row(2, "2.2.2.2", 2); // p200, p201 — rewrite to share
        // Two endpoints pointing at the SAME `Protocol` rows: the identity
        // dedup collision (protocol config equal, only host/port differs).
        for (l, pid) in ep2.links.iter_mut().zip([100_i64, 101]) {
            l.protocol_id = leas_db::models::ProtocolId::new(pid);
        }
        ep2.protocols = ep1.protocols.clone();
        ep1.endpoint.domain = String::new();
        ep1.endpoint.sub_domain = String::new();
        ep2.endpoint.domain = String::new();
        ep2.endpoint.sub_domain = String::new();
        state.endpoints = vec![ep1, ep2];
        state.selected_index = 1;

        // Ping ep2's p101 link.
        state.testing_profiles.insert((2, 101));
        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 2,
            protocol_id: 101,
            test_type: TestType::TcpPing,
            latency_ms: Some(45),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // Result lands on ep2's p101 row; ep1's p101 row untouched. (The live
        // re-sort moves the now-measured p101 to the top of ep2's sub-table,
        // so look up by protocol id, not index.)
        let ep2_p101 = state.endpoints[1]
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 101)
            .expect("ep2 p101 link");
        assert_eq!(
            ep2_p101.latency,
            Some(Latency::Fast { delay: 45 }),
            "probing endpoint's own row must carry the result"
        );
        assert_eq!(
            state.endpoints[0]
                .links
                .iter()
                .find(|l| l.protocol_id.get() == 101)
                .unwrap()
                .latency,
            None,
            "sibling endpoint must stay untouched"
        );

        // The same protocol on ep1 is a DIFFERENT link: its own result must
        // NOT be dropped by a per-protocol dedupe guard, and must write ep1's
        // row.
        state.testing_profiles.insert((1, 101));
        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 1,
            protocol_id: 101,
            test_type: TestType::TcpPing,
            latency_ms: Some(60),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert_eq!(
            state.endpoints[0]
                .links
                .iter()
                .find(|l| l.protocol_id.get() == 101)
                .unwrap()
                .latency,
            Some(Latency::Fast { delay: 60 }),
            "second endpoint's result processed, not dropped"
        );
        // ep2's earlier result survives the second event (no cross-write).
        assert_eq!(
            state.endpoints[1]
                .links
                .iter()
                .find(|l| l.protocol_id.get() == 101)
                .unwrap()
                .latency,
            Some(Latency::Fast { delay: 45 })
        );
    }

    #[tokio::test]
    async fn real_ping_success_promotes_lowest_latency_link() {
        // User scenario: first protocol fails real ping, second succeeds.
        // The single-row view must follow the successful (best) protocol, not
        // the failed one. Regression: sort keeps the failed link first under
        // a transient DNS-unresolved tier, so promotion must be explicit.
        let (mut state, tx) = event_state().await;
        let mut row = fake_row(1, "h1.example", 2); // p100, p101
        // (a name fixture is already a DNS host)
        row.links[0].error = Some(leas_db::models::ErrorInfo {
            kind: leas_db::models::ProfileErr::Real,
            text: "timeout".into(),
        });
        row.links[0].last_seen_at = crate::ops::profiles::test_support::ts(200);
        row.links[1].latency = Some(Latency::Real {
            delay: 90,
            ip: None,
        });
        row.links[1].last_seen_at = crate::ops::profiles::test_support::ts(100);
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.testing_profiles.insert((1, 101));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 1,
            protocol_id: 101,
            test_type: TestType::RealPing,
            latency_ms: Some(40),
            speed_bps: None,
            ip_info: Some("5.6.7.8|US".to_string()),
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        let row = &state.endpoints[0];
        // Pre-fix: active stayed p100 (failed) — tier-5 recency sort kept it
        // first, so the row showed [real] + no delay. Post-fix: promotion.
        let active = row.active_link().expect("active link");
        assert_eq!(
            active.protocol_id,
            leas_db::models::ProtocolId::new(101),
            "best real-ok link must become the preferred protocol"
        );
        assert!(matches!(
            active.latency,
            Some(Latency::Real { delay: 40, .. })
        ));
    }

    #[tokio::test]
    async fn real_ping_result_restores_sub_table_and_remaps_selection() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 3, 7); // p7, p8, p9
        set_delay(&mut row, 9, 50, false); // fast-ok
        row.endpoint.domain = String::new();
        row.endpoint.sub_domain = String::new();
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.selected_sub = Some(2); // points at p9 before the sort
        state.filter_cache_valid.set(false);
        // The SpeedTestResult dedupe guard drops events for protocols not in
        // `testing_profiles`; production seeds it when a ping starts.
        state.testing_profiles.insert((100, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 8,
            test_type: TestType::RealPing,
            latency_ms: Some(120),
            speed_bps: None,
            ip_info: Some("1.2.3.4|US".to_string()),
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // p8 (real 120) above p9 (fast 50) — tier beats latency; p7 untested last.
        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![8, 9, 7]);
        // selected_sub followed p9 to its new index 1.
        assert_eq!(state.selected_sub, Some(1));
        // p8's latency persisted as a Real measurement (with the ip part).
        assert!(matches!(
            state.endpoints[0].links[0].latency,
            Some(Latency::Real { delay: 120, ip: Some(ref s) }) if s == "1.2.3.4"
        ));
    }

    #[tokio::test]
    async fn real_ping_failure_demotes_below_untested() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 2, 7); // p7, p8
        set_delay(&mut row, 7, 50, true); // stored real-ok
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);
        state.testing_profiles.insert((100, 7));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 7,
            test_type: TestType::RealPing,
            latency_ms: None,
            speed_bps: None,
            ip_info: None,
            error: Some("timeout".to_string()),
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![8, 7]); // fresh real failure sinks below untested
        // The failure persisted as a Real-kind error marker.
        assert_eq!(
            state.endpoints[0].links[1].error.as_ref().map(|e| e.kind),
            Some(ProfileErr::Real)
        );
    }

    #[tokio::test]
    async fn fast_ping_result_sorts_sub_table() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 2, 7); // p7, p8
        set_delay(&mut row, 7, 200, true); // real-ok
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);
        state.testing_profiles.insert((100, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 8,
            test_type: TestType::TcpPing,
            latency_ms: Some(15),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![7, 8]); // real-ok 200 still above fast-ok 15
        assert!(matches!(
            state.endpoints[0].links[1].latency,
            Some(Latency::Fast { delay: 15 })
        ));
    }

    #[tokio::test]
    async fn udp_result_does_not_resort_and_records_udp_latency() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 2, 7); // p7, p8
        set_delay(&mut row, 7, 200, false); // fast-ok
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);
        state.testing_profiles.insert((100, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 8,
            test_type: TestType::UdpTest,
            latency_ms: Some(50),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // UDP must not trigger a re-sort: p8 (udp-ok 50ms) stays below p7
        // (fast-ok 200ms) in the CURRENT (unsorted) order.
        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![7, 8]);
        // Latency persisted (fast-class semantics).
        assert!(matches!(
            state.endpoints[0].links[1].latency,
            Some(Latency::Fast { delay: 50 })
        ));
    }

    #[tokio::test]
    async fn dns_unresolved_endpoint_sinks_after_result() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 2, 7); // p7, p8
        set_delay(&mut row, 7, 50, true); // real-ok
        // (already a DNS host)
        row.resolved_ips.clear(); // a DNS host with no resolved address
        state.endpoints = vec![row]; // no endpoint_info entry -> unresolved
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);
        state.testing_profiles.insert((100, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 8,
            test_type: TestType::RealPing,
            latency_ms: Some(10),
            speed_bps: None,
            ip_info: Some("1.2.3.4|US".to_string()),
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // dns tier sinks both protocols to the bottom. Within the dns tier the
        // tiebreak is `last_seen_at desc, then id asc`; both links share
        // last_seen ts(0), so id asc wins -> [7, 8].
        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![7, 8]);
    }

    #[tokio::test]
    async fn cancelled_real_ping_does_not_rank_untested_as_real_ok() {
        let (mut state, tx) = event_state().await;
        let row = row_with_protocols(100, 2, 7); // p7, p8, both untested
        state.endpoints = vec![row];
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);
        state.testing_profiles.insert((100, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 100,
            protocol_id: 8,
            test_type: TestType::RealPing,
            latency_ms: None,
            speed_bps: None,
            ip_info: None,
            error: Some("Cancelled".to_string()),
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // A Cancelled event mutates nothing: no latency, no error marker —
        // p8 stays untested and is never hoisted to the real-ok tier.
        let link = state.endpoints[0]
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 8)
            .unwrap();
        assert!(link.latency.is_none());
        assert!(link.error.is_none());
        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![7, 8]); // order unchanged, still untested tier
    }

    #[tokio::test]
    async fn endpoint_info_flip_to_resolved_restores_priority_order() {
        let (mut state, tx) = event_state().await;
        let mut row = row_with_protocols(100, 2, 7); // p7, p8
        set_delay(&mut row, 7, 50, false); // fast-ok
        set_delay(&mut row, 8, 10, true); // real-ok
        // (already a DNS host)
        row.resolved_ips.clear(); // a DNS host with no resolved address
        state.endpoints = vec![row]; // no endpoint_info entry -> unresolved
        state.selected_index = 0;
        state.selected_sub = None;
        state.filter_cache_valid.set(false);

        tx.send(CoreEvent::EndpointInfoUpdated {
            endpoint_id: 100,
            info: EndpointInfo {
                resolved_ips: vec!["1.2.3.4".parse().unwrap()],
                ..EndpointInfo::default()
            },
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        // Unresolved: both sink to the dns tier ([7, 8] by id). Once the DNS
        // flip resolves, p8 (real-ok) rises above p7 (fast-ok) -> [8, 7].
        let ids: Vec<i64> = state.endpoints[0]
            .links
            .iter()
            .map(|l| l.protocol_id.get())
            .collect();
        assert_eq!(ids, vec![8, 7]);
    }

    #[tokio::test]
    async fn batch_ended_clears_the_meters_and_rearms_the_stop_flag() {
        let (mut state, tx) = event_state().await;

        // The batch task publishes the meters itself (they are shared, not
        // event-carried); the event only closes the batch.
        state.batch_progress = Some(Arc::new(crate::types::BatchMeters::default()));
        state.speed_test_stop.store(true, Ordering::Relaxed);

        tx.send(CoreEvent::BatchEnded).await.unwrap();
        assert!(state.poll_core_events().await);
        assert!(state.batch_progress.is_none());
        assert!(!state.speed_test_stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn stop_flag_survives_last_result_while_batch_active() {
        // T19: the auto-reset must NOT clear the stop flag during a batch
        // (the phase-1 → phase-2 transition would otherwise lose a stop
        // pressed mid-batch). Only after the batch's progress is gone does a
        // drained result re-arm the flag.
        let (mut state, tx) = event_state().await;
        state.batch_progress = Some(Arc::new(crate::types::BatchMeters::default()));
        state.speed_test_stop.store(true, Ordering::Relaxed);
        state.testing_profiles.insert((0, 8));

        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 0,
            protocol_id: 8,
            test_type: TestType::TcpPing,
            latency_ms: Some(1),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert!(
            state.speed_test_stop.load(Ordering::Relaxed),
            "stop flag survives while a batch is active"
        );

        // Batch ends (progress cleared) → the next drained result resets it.
        state.batch_progress = None;
        state.testing_profiles.insert((0, 9));
        tx.send(CoreEvent::SpeedTestResult {
            endpoint_id: 0,
            protocol_id: 9,
            test_type: TestType::RealPing,
            latency_ms: Some(20),
            speed_bps: None,
            ip_info: None,
            error: None,
            purge: None,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        assert!(!state.speed_test_stop.load(Ordering::Relaxed));
    }

    #[test]
    fn render_route_event_covers_all_five_variants() {
        use leas_route::events::RouteEvent as Re;

        let line = render_route_event(&Re::DecisionApplied {
            rule_name: Some("ads".into()),
            tag: Some("proxy".into()),
            sni: Some("example.com".into()),
            at: jiff::Timestamp::from_second(1_700_000_000).expect("ts"),
        });
        assert_eq!(line.target, "route");
        assert_eq!(line.level, "info");
        assert_eq!(
            line.message,
            "route: ads → proxy sni=example.com (2023-11-14T22:13:20Z)"
        );
        assert_eq!(line.timestamp_nanos, 1_700_000_000_000_000_000);

        // Default fall-through: no rule name, no tag, no sni.
        let line = render_route_event(&Re::DecisionApplied {
            rule_name: None,
            tag: None,
            sni: None,
            at: jiff::Timestamp::from_second(1).expect("ts"),
        });
        assert_eq!(
            line.message,
            "route: <rule> → <default> (1970-01-01T00:00:01Z)"
        );

        let line = render_route_event(&Re::Resolved {
            host: "example.com".into(),
            ips: vec![
                "1.2.3.4".parse::<std::net::IpAddr>().unwrap(),
                "::1".parse::<std::net::IpAddr>().unwrap(),
            ],
            at: jiff::Timestamp::from_second(2).expect("ts"),
        });
        assert_eq!(line.target, "route");
        assert_eq!(
            line.message,
            "route: resolved example.com → [1.2.3.4, ::1] (1970-01-01T00:00:02Z)"
        );

        let line = render_route_event(&Re::NetworkBreakdown {
            failed_probe: "gstatic".into(),
            at: jiff::Timestamp::from_second(3).expect("ts"),
        });
        assert_eq!(
            line.message,
            "route: NETWORK BREAKDOWN probe gstatic (1970-01-01T00:00:03Z)"
        );

        let line = render_route_event(&Re::ProbeRecovered {
            probe: "gstatic".into(),
            at: jiff::Timestamp::from_second(4).expect("ts"),
        });
        assert_eq!(
            line.message,
            "route: probe recovered gstatic (1970-01-01T00:00:04Z)"
        );

        let line = render_route_event(&Re::CompileWarning {
            rule_index: 7,
            message: "unknown key".into(),
        });
        assert_eq!(line.message, "route: compile warning rule#7: unknown key");
        assert_eq!(line.timestamp_nanos, 0);
    }

    #[tokio::test]
    async fn route_event_lands_in_log_cache() {
        let (mut state, tx) = event_state().await;
        tx.send(CoreEvent::Route(
            leas_route::events::RouteEvent::ProbeRecovered {
                probe: "gstatic".into(),
                at: jiff::Timestamp::from_second(5).expect("ts"),
            },
        ))
        .await
        .unwrap();
        assert!(state.poll_core_events().await);
        let back = state.log_cache.back().expect("route line cached");
        assert_eq!(back.target, "route");
        assert_eq!(
            back.message,
            "route: probe recovered gstatic (1970-01-01T00:00:05Z)"
        );
        assert_eq!(back.timestamp_nanos, 5_000_000_000);
    }

    #[tokio::test]
    async fn spawn_route_event_forwarder_converts_events() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (core_tx, mut core_rx) = tokio::sync::mpsc::channel(16);
        super::spawn_route_event_forwarder(rx, core_tx);
        tx.send(leas_route::events::RouteEvent::NetworkBreakdown {
            failed_probe: "gstatic".into(),
            at: jiff::Timestamp::from_second(6).expect("ts"),
        })
        .unwrap();
        drop(tx); // close the route stream so the forwarder can exit later
        let ev = core_rx.recv().await.expect("forwarded event");
        match ev {
            CoreEvent::Route(leas_route::events::RouteEvent::NetworkBreakdown {
                failed_probe,
                at,
            }) => {
                assert_eq!(&*failed_probe, "gstatic");
                assert_eq!(at, jiff::Timestamp::from_second(6).expect("ts"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
