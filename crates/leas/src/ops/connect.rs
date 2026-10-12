use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;

use leas_core::grpc_client;
use leas_core::{
    BuildParams, CLASH_API_PORT, ConfigBuilder, CoreType, RealCoreManager,
    config_builder::clash_mixin::parse_clash_mixin, find_binary,
};
use leas_db::models::{DnsSetting, EndpointId, RoutingRule};
use leas_native::capability;
use leas_proto::proto_spec::{CoreType as ProtoCoreType, ProtocolConfig, ProtocolKind};

use super::native_connect;

use crate::AppState;
use crate::parse_core_log_line;
use crate::types::CoreEvent;
use crate::{ClashTraffic, try_send_or_warn};
use futures_util::StreamExt;
use std::sync::LazyLock;

/// Shared reqwest client for the sing-box Clash API stream: one connection
/// pool per process instead of one `Client::new()` per connection session.
static CLASH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    leas_core::ensure_tls_provider();
    reqwest::Client::new()
});

/// Map one sing-box clash `/traffic` line to its `StatsUpdate` event.
///
/// sing-box emits one JSON line per second with that second's traffic delta
/// since the previous line, so the event carries the per-line delta — the
/// same semantics as the xray gRPC poller (`query_stats(..., reset = true)`).
/// The events handler accumulates deltas into the persisted row; sending a
/// cumulative session total here would double-count on every event.
const fn clash_stats_event(protocol_id: i64, t: &ClashTraffic) -> CoreEvent {
    CoreEvent::StatsUpdate {
        protocol_id,
        today_up: t.up,
        today_down: t.down,
        total_up: t.up,
        total_down: t.down,
    }
}

/// How long a new session waits for the previous session task to finish its
/// teardown before it binds its own listeners.
///
/// AGENTS.md decision 3 — one core at a time, the in-process server included:
/// the stop signal only *asks* the previous session to stop, so a new session
/// that does not wait binds onto still-held ports (EADDRINUSE) and races the
/// old task's closing `Disconnected`.
const PREV_SESSION_TEARDOWN: Duration = Duration::from_secs(5);

/// How long `disconnect` lets the session task run its own teardown
/// (`server.shutdown()` + `Disconnected`) before aborting it.
const DISCONNECT_TEARDOWN: Duration = Duration::from_secs(3);

/// Loud downgrade lines: what refused the native core, and what runs instead.
const REFUSED_KIND: &str =
    "native core has no implementation for this protocol kind; using the subprocess core";
const REFUSED_PROXY_ALL: &str =
    "native core is proxy-all: routing rules / DNS settings need xray-core";
const REFUSED_UNLOADED: &str = "profile config not loaded; native core skipped, using xray-core";
const REFUSED_CAPABILITY: &str =
    "native core does not support this profile config; using xray-core";

/// True when a `protocol_core_overrides` value asks for the in-process core.
///
/// `auto` asks for it too: it is the config-level "prefer native" answer, and
/// preferring native is exactly what the capability gate decides. Neither value
/// bypasses that gate.
const fn asks_native(forced: Option<CoreType>) -> bool {
    matches!(forced, Some(CoreType::Native | CoreType::Auto))
}

/// Resolve the core that serves one connect, plus the gate that refused the
/// native core when it was asked for.
///
/// `link_core` is the link's persisted stamp — always concrete — and the only
/// legal *subprocess* answer: `ConfigBuilder::build` dispatches on
/// `link.core_type`, so a runtime core that disagreed with the stamp would feed
/// one core's JSON to the other's binary. A `protocol_core_overrides` value of
/// `xray`/`sing-box` therefore only vetoes native; `native`/`auto` asks for
/// native and still faces the capability gate.
///
/// Native is asked for by that override, or by an xray-stamped link on one of
/// the six native kinds — the connect-time replacement for the old parse-time
/// `Auto` stamp, so nothing native-specific is persisted.
fn resolve_runtime_core(
    link_core: CoreType,
    kind: ProtocolKind,
    forced: Option<CoreType>,
    config: Option<&ProtocolConfig>,
    proxy_all_blocked: bool,
) -> (CoreType, Option<&'static str>) {
    let forces_legacy = matches!(forced, Some(CoreType::Xray | CoreType::SingBox));
    let asked_for_native = asks_native(forced) || (!forces_legacy && link_core == CoreType::Xray);
    if !asked_for_native {
        return (link_core, None);
    }
    if !capability::kind_supported(kind) {
        // Every xray-stamped non-native kind lands here: for those the
        // subprocess core *is* the expected answer, so only an explicit native
        // override earns a line.
        return (link_core, asks_native(forced).then_some(REFUSED_KIND));
    }
    if proxy_all_blocked {
        return (link_core, Some(REFUSED_PROXY_ALL));
    }
    let Some(config) = config else {
        return (link_core, Some(REFUSED_UNLOADED));
    };
    if capability::supported(kind, config) {
        (CoreType::Native, None)
    } else {
        (link_core, Some(REFUSED_CAPABILITY))
    }
}

/// Connect to a profile by starting the appropriate core (xray-core or sing-box).
pub fn connect_to_profile(state: &mut AppState, endpoint_id: i64) {
    if state.connecting {
        return;
    }

    let (endpoint, addresses, protocol_id, proto_kind) = {
        let Some(row) = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == endpoint_id)
        else {
            state.log_trace(
                "error",
                "tui::ops::connect",
                "Profile not found for connection",
            );
            return;
        };
        let Some((link, protocol)) = row.active_protocol() else {
            // T8+9: linkless endpoints are valid rows — nothing to connect.
            state.log_trace(
                "error",
                "tui::ops::connect",
                "Endpoint has no protocol links to connect",
            );
            return;
        };
        (
            row.endpoint.clone(),
            row.resolved_ips.clone(),
            link.protocol_id,
            protocol.proto_kind,
        )
    };

    // If already connected/disconnecting, send stop signal first
    if let Some(tx) = state.disconnect_tx.take() {
        let _ = tx.send(());
    }

    // Create disconnect signal channel
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    state.disconnect_tx = Some(stop_tx);
    state.connecting = true;
    state.connected_protocol_id = Some(endpoint_id);
    state.connection_error = None;

    // Deferred-resolution trigger: connect does real networking, so resolve
    // the inbound host now (force — bypasses the TTL cache).
    crate::ops::enrich::spawn_dns_resolve(state, endpoint.id.get(), true);

    // "Last Used" = connect initiation: DB write + in-memory row so the
    // sub-table refreshes without a reload. `update_last_used` sets both
    // `last_used_at` and `last_seen_at` to the same ts (old semantics).
    let now = leas_db::models::now_epoch();
    let lu_endpoint_id = EndpointId::new(endpoint.id.get());
    let lu_db = state.db.clone();
    tokio::spawn(async move {
        if let Err(e) = lu_db
            .update_last_used(protocol_id, lu_endpoint_id, now)
            .await
        {
            tracing::warn!(target: "tui::ops::connect", "update_last_used failed: {e}");
        }
    });
    if let Some(r) = state
        .endpoints
        .iter_mut()
        .find(|r| r.endpoint.id == endpoint.id)
        && let Some(link) = r.links.iter_mut().find(|l| l.protocol_id == protocol_id)
    {
        link.last_used_at = Some(now);
        // Mirror the DB write so the sub-table's displayed last_seen matches
        // the DB staleness classification between reloads.
        link.last_seen_at = now;
    }
    let tx = if let Some(tx) = &state.core_event_tx {
        tx.clone()
    } else {
        state.connecting = false;
        state.log_trace(
            "error",
            "tui::ops::connect",
            "Core event channel not initialized",
        );
        return;
    };

    // Runtime core selection needs the loaded config, so the task builds
    // `BuildParams` itself from these hoisted values (flags follow the
    // resolved core, not the stamped link value).
    let param_log_level = state.config.core.log_level.clone();
    let param_socks_port = state.config.inbound.socks_port;
    let param_http_port = state.config.inbound.http_port;
    let param_listen = state.config.inbound.listen.clone();
    let param_sniffing = state.config.inbound.sniffing;
    let param_clash_api_port = state.config.clash_api_port;
    let param_mux = if state.config.mux.enabled {
        Some(serde_json::json!({
            "protocol": state.config.mux.protocol,
            "max_connections": state.config.mux.max_connections,
            "min_streams": state.config.mux.min_streams,
            "max_streams": state.config.mux.max_streams,
            "padding": state.config.mux.padding,
        }))
    } else {
        None
    };
    let param_clash_mixin = state
        .config
        .clash_mixin
        .as_deref()
        .and_then(parse_clash_mixin);
    let param_skip_cert_verify = state.config.core.skip_cert_verify;
    let param_core_overrides = state.config.core.protocol_core_overrides.clone();

    // Routing comes from the already-loaded rules; DNS settings are loaded
    // inside the task (async read) with a typed default fallback.
    let routing: Vec<RoutingRule> = state.routing_rules.clone();
    let db = state.db.clone();

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("leas");
    let bin_dir = config_dir.join("bin");
    let bin_configs_dir = config_dir.join("binConfigs");

    // Create log forwarding channel
    let (log_line_tx, mut log_line_rx) = mpsc::channel::<String>(512);
    let state_log_sender = state.log_sender_tx.clone();

    // One core at a time: hand the previous session's task to the new one so it
    // can wait out that teardown before binding its own listeners.
    let prev_task = state.core_task_handle.take();
    let handle = tokio::spawn(async move {
        // 0a. Wait out the previous session's teardown — the stop signal above
        //     only asked it to stop. A wedged task is aborted so its listeners
        //     are released either way.
        if let Some(mut prev) = prev_task
            && tokio::time::timeout(PREV_SESSION_TEARDOWN, &mut prev)
                .await
                .is_err()
        {
            tracing::warn!(
                target: "tui::ops::connect",
                secs = PREV_SESSION_TEARDOWN.as_secs(),
                "previous core session did not finish teardown; aborting it"
            );
            prev.abort();
        }
        // Cancelled while waiting (disconnect, or another connect took over):
        // bind nothing. This session never emitted `Connected`, so it must not
        // emit `Disconnected` either.
        if stop_rx.try_recv().is_ok() {
            return;
        }

        // 0b. Load the Protocol row with config included (the EndpointRow
        //     list ships unloaded deferred JSON).
        let protocol = match crate::state::load_protocol_with_config(&db, protocol_id).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::Error("Protocol row not found for connection".to_string()),
                    "protocol_not_found",
                );
                return;
            }
            Err(e) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::Error(format!("Failed to load protocol: {e}")),
                    "protocol_load_error",
                );
                return;
            }
        };
        let dns = match db.get_dns_settings().await {
            Ok(Some(d)) => d,
            _ => DnsSetting {
                id: "default".to_string(),
                name: None,
                servers: Vec::new(),
                hosts: Vec::new(),
                query_strategy: None,
                disable_cache: false,
                disable_fallback: false,
                client_ip: None,
                cache_ttl_secs: None,
            },
        };

        // 0.5. Runtime core. The core is DERIVED (the per-pair stamp is gone,
        //     db-rewamp D3) from the LOADED protocol — `shadowsocks_method`
        //     needs the real config, and the page row's is unloaded, so a
        //     legacy-cipher SS row would otherwise default to xray-core and
        //     fail at build. Native preference is decided here too, because
        //     only here can the capability gate run.
        let forced = param_core_overrides
            .get(&proto_kind.to_string())
            .and_then(|s| s.parse::<CoreType>().ok());
        let link_core = match leas_proto::proto_spec::core_mapping::resolve_core(
            proto_kind,
            match forced {
                Some(CoreType::Xray) => Some(ProtoCoreType::Xray),
                Some(CoreType::SingBox) => Some(ProtoCoreType::SingBox),
                Some(CoreType::Native | CoreType::Auto) | None => None,
            },
            leas_core::config_builder::shadowsocks_method(&protocol).as_deref(),
        ) {
            ProtoCoreType::Xray => CoreType::Xray,
            ProtoCoreType::SingBox => CoreType::SingBox,
        };
        // The native core is proxy-all — no routing engine, no DNS server — so
        // a profile with routing rules or non-default DNS keeps the subprocess
        // core. Decided before the capability gate so the `BuildParams` api
        // flags below follow the final runtime core.
        let proxy_all_blocked =
            !routing.is_empty() || !dns.servers.is_empty() || !dns.hosts.is_empty();
        let loaded_config = if protocol.config.is_unloaded() {
            None
        } else {
            Some(&protocol.config.get().0)
        };
        let (runtime_core, refused) = resolve_runtime_core(
            link_core,
            proto_kind,
            forced,
            loaded_config,
            proxy_all_blocked,
        );
        if let Some(reason) = refused {
            tracing::warn!(
                target: "tui::ops::connect",
                host = %endpoint.dns_name(),
                kind = %proto_kind,
                core = %runtime_core,
                rules = routing.len(),
                dns_servers = dns.servers.len(),
                dns_hosts = dns.hosts.len(),
                "{reason}"
            );
            if asks_native(forced) {
                tracing::warn!(
                    target: "tui::ops::connect",
                    host = %endpoint.dns_name(),
                    kind = %proto_kind,
                    core = %runtime_core,
                    "protocol_core_overrides asked for the native core: override NOT honored"
                );
            }
        }
        let params = BuildParams {
            v2ray_api_enabled: runtime_core == CoreType::Xray,
            clash_api_enabled: runtime_core == CoreType::SingBox,
            log_level: param_log_level,
            socks_port: param_socks_port,
            http_port: param_http_port,
            listen: param_listen,
            sniffing: param_sniffing,
            clash_api_port: param_clash_api_port,
            mux: param_mux,
            clash_mixin: param_clash_mixin,
            skip_cert_verify: param_skip_cert_verify,
        };
        if runtime_core == CoreType::Native {
            native_connect::run_native_session(
                &params,
                &endpoint,
                &addresses,
                &protocol,
                &tx,
                &state_log_sender,
                stop_rx,
                protocol_id.get(),
            )
            .await;
            return;
        }

        // 1. Build config
        let backend_config = match ConfigBuilder::build(
            &endpoint,
            &addresses,
            &protocol,
            match runtime_core {
                CoreType::Xray => ProtoCoreType::Xray,
                CoreType::SingBox => ProtoCoreType::SingBox,
                CoreType::Auto | CoreType::Native => {
                    try_send_or_warn(
                        &tx,
                        CoreEvent::Error(
                            "internal: non-subprocess core reached the builder".into(),
                        ),
                        "config_build_error",
                    );
                    return;
                }
            },
            &params,
            &routing,
            &dns,
        ) {
            Ok(c) => c,
            Err(e) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::Error(format!("Config build failed: {e}")),
                    "config_build_error",
                );
                return;
            }
        };

        // 2. Find binary
        let Some(bin_path) = find_binary(runtime_core, &bin_dir) else {
            try_send_or_warn(
                &tx,
                CoreEvent::Error(
                    "Core binary not found. Place it in ~/.config/leas/bin/ or install in PATH."
                        .to_string(),
                ),
                "binary_not_found",
            );
            return;
        };
        // 3. Start core
        let mut manager = RealCoreManager::new(bin_configs_dir, log_line_tx);
        if let Err(e) = manager
            .start(
                runtime_core,
                &backend_config,
                &bin_path,
                params.clash_mixin.as_ref(),
            )
            .await
        {
            try_send_or_warn(
                &tx,
                CoreEvent::Error(format!("Failed to start core: {e}")),
                "core_start_error",
            );
            return;
        }

        // 3b. Readiness probe: wait for the core's proxy port to open
        let proxy_port = params.socks_port;
        if proxy_port > 0 {
            let probe_start = std::time::Instant::now();
            loop {
                if probe_start.elapsed() > std::time::Duration::from_secs(10) {
                    break;
                }
                match tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await {
                    Ok(_) => break,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
                }
            }
        }

        // 4. Signal connected
        try_send_or_warn(&tx, CoreEvent::Connected(runtime_core), "connected");

        // Forward stderr log lines as CoreEvent::LogLine
        let log_tx = tx.clone();
        let log_sender = state_log_sender.clone();
        tokio::spawn(async move {
            while let Some(line) = log_line_rx.recv().await {
                let (level, target, message, ts_nanos) = parse_core_log_line(&line, runtime_core);
                let timestamp_nanos = ts_nanos.unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as i64
                });
                // Write to log storage via bounded channel: `try_send` never
                // blocks the executor; on a full queue the line drops (counted
                // on the layer) instead of parking this task per line.
                if let Some(ref sender) = log_sender {
                    let _ = sender.try_send(leas_core::log_heed::LogMessage {
                        level: level.clone(),
                        target: target.clone(),
                        message: message.clone(),
                        timestamp_nanos: timestamp_nanos as u64,
                    });
                }
                // Forward to TUI
                try_send_or_warn(
                    &log_tx,
                    CoreEvent::LogLine {
                        level,
                        target,
                        message,
                        timestamp_nanos,
                    },
                    "log_line",
                );
            }
        });

        let profile_id = protocol_id.get();

        if runtime_core == CoreType::Xray {
            // === gRPC polling loop (xray-core) ===
            let provider = match grpc_client::create_stats_provider().await {
                Ok(p) => Some(p),
                Err(e) => {
                    try_send_or_warn(
                        &tx,
                        CoreEvent::StatsError(format!("Stats API unavailable: {e}")),
                        "stats_api_unavailable",
                    );
                    None
                }
            };
            let poll_interval = std::time::Duration::from_secs(3);
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.tick().await;
            let mut sys_tick_counter = 0u8;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = ticker.tick() => {
                        if let Some(ref provider) = provider {
                            match provider.query_stats("outbound>>>*>>>traffic>>>*", true).await {
                                Ok(rows) => {
                                    let mut today_up = 0i64;
                                    let mut today_down = 0i64;
                                    for stat in &rows {
                                        if stat.name.contains(">>>uplink") {
                                            today_up += stat.value;
                                        } else if stat.name.contains(">>>downlink") {
                                            today_down += stat.value;
                                        }
                                    }
                                    try_send_or_warn(&tx, CoreEvent::StatsUpdate {
                                        protocol_id: profile_id,
                                        today_up,
                                        today_down,
                                        total_up: today_up,
                                        total_down: today_down,
                                    }, "stats_update");
                                }
                                Err(e) => {
                                try_send_or_warn(&tx, CoreEvent::StatsError(format!("Stats query failed: {e}")), "stats_query_err");
                                }
                            }
                            // sys stats every 3rd tick (~9s)
                            sys_tick_counter += 1;
                            if sys_tick_counter >= 3 {
                                sys_tick_counter = 0;
                                match provider.get_sys_stats().await {
                                    Ok(sys) => { try_send_or_warn(&tx, CoreEvent::SysStatsUpdate(sys), "sys_stats_update"); }
                                    Err(e) => {
                                        try_send_or_warn(&tx, CoreEvent::StatsError(format!("Sys stats query failed: {e}")), "sys_stats_err");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // === Sing-box Clash API /traffic streaming ===
            let clash_port = params.clash_api_port.unwrap_or(CLASH_API_PORT);
            let url = format!("http://127.0.0.1:{clash_port}/traffic");
            match CLASH_CLIENT.get(&url).send().await {
                Ok(resp) => {
                    let mut stream = Box::pin(resp.bytes_stream());
                    // `split_to` advances the start offset without memmove; a
                    // traffic line is ~50 B/s, so retention is one partial line.
                    let mut buf = bytes::BytesMut::new();
                    loop {
                        tokio::select! {
                            _ = &mut stop_rx => break,
                            chunk = stream.next() => {
                                match chunk {
                                    Some(Ok(bytes)) => {
                                        buf.extend_from_slice(&bytes);
                                        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                                            let trimmed = buf[..=pos].trim_ascii();
                                            if let Ok(t) = serde_json::from_slice::<ClashTraffic>(trimmed) {
                                                // Per-line deltas (sing-box
                                                // emits each second's traffic
                                                // since the last line) — the
                                                // same delta semantics as the
                                                // xray gRPC poller, so the
                                                // stats handler's accumulation
                                                // never double-counts.
                                                try_send_or_warn(
                                                    &tx,
                                                    clash_stats_event(profile_id, &t),
                                                    "clash_stats_update",
                                                );
                                            }
                                            let _ = buf.split_to(pos + 1);
                                        }
                                    }
                                    Some(Err(e)) => {
                                        try_send_or_warn(&tx, CoreEvent::StatsError(
                                            format!("Clash API stream error: {e}")
                                        ), "clash_stream_err");
                                        break;
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    try_send_or_warn(
                        &tx,
                        CoreEvent::StatsError(format!(
                            "Clash API unavailable (is sing-box running?): {e}"
                        )),
                        "clash_unavailable",
                    );
                }
            }
        }

        // 6. Stop core
        let _ = manager.stop().await;

        // 7. Signal disconnected
        try_send_or_warn(&tx, CoreEvent::Disconnected, "disconnected");
    });
    state.core_task_handle = Some(handle);
}

/// Disconnect the currently running core.
pub fn disconnect(state: &mut AppState) {
    // Flush the final traffic delta: a poller tick landing just before the
    // stop can still sit in the event channel, unprocessed (the event loop
    // drains once per frame). Accumulate those deltas into the owning link
    // and persist the final row state once. Traffic since the last poll tick
    // (≤ one poll interval — 3s xray / 1s sing-box) was never captured as an
    // event and is dropped by design; the T21 handler already persisted
    // every processed tick, so the row is current as of the last tick.
    let flushed = crate::ops::events::drain_pending_stats_updates(state);
    if !flushed.is_empty() {
        // Stage, don't commit: the traffic group is written by the flush task
        // (one transaction per window), and the UI task never waits on it.
        for link in &flushed {
            state.link_stage.stage(link, leas_db::LinkGroups::TRAFFIC);
        }
        // `disconnect` is synchronous, so the flush is spawned (as the old
        // per-row writes were) — but it is now one transaction, not N.
        let writer = std::sync::Arc::clone(&state.link_stage);
        tokio::spawn(async move {
            if let Err(e) = writer.flush().await {
                tracing::warn!(target: "tui::ops::connect", "final stats flush failed: {e}");
            }
        });
    }
    if let Some(tx) = state.disconnect_tx.take() {
        let _ = tx.send(());
    }
    if let Some(mut handle) = state.core_task_handle.take() {
        // Let the session task run its own teardown — the native core's
        // `server.shutdown()` and the closing `Disconnected` live there — and
        // abort only a wedged one. The waiter replaces the handle so a
        // following connect still serializes on this teardown (those listeners
        // must be gone before new ones bind), while the UI thread returns now.
        state.core_task_handle = Some(tokio::spawn(async move {
            if tokio::time::timeout(DISCONNECT_TEARDOWN, &mut handle)
                .await
                .is_err()
            {
                tracing::warn!(
                    target: "tui::ops::connect",
                    secs = DISCONNECT_TEARDOWN.as_secs(),
                    "core session did not stop in time; aborting it"
                );
                handle.abort();
            }
        }));
    }
    state.connected_core = None;
    state.connected_protocol_id = None;
    state.connecting = false;
    // Session state: drop the error marker and the actions-log traffic
    // deltas so a disconnected session renders as "Disconnected", never as a
    // stale error or a frozen traffic segment.
    state.connection_error = None;
    state.current_traffic_up = 0;
    state.current_traffic_down = 0;
    state.log_trace("info", "core::process", "Disconnected");
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use leas_config::AppConfig;
    use leas_db::models::{
        ErrorInfo, Latency, ProfileErr, ProfileStats, ProtocolId, Security, Transport,
    };
    use leas_proto::proto_spec::common::TransportConfig;
    use leas_proto::proto_spec::{
        PlaceholderConfig, ProtocolConfig, ProtocolKind, SecurityConfig, SecurityType,
        TransportType,
    };
    use toasty::{Deferred, Json};

    use crate::ops::profiles::test_support::fake_row;

    use super::*;

    use rstest::rstest;

    /// A `Protocol` row whose config is a placeholder (`Redirect`): the
    /// `ConfigBuilder::build` outbound injection errors on BOTH cores, so a
    /// connect attempt fails deterministically at config build — before any
    /// binary lookup or core start.
    fn placeholder_protocol(id: i64) -> leas_db::models::Protocol {
        let settings = serde_json::json!({
            "protocol_settings": {"password": "sekrit"},
            "stream_settings": {},
        });
        leas_db::models::Protocol {
            id: ProtocolId::new(id),
            sig: id,
            proto_kind: ProtocolKind::Redirect,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Redirect(PlaceholderConfig::new(
                "redirect".to_string(),
                serde_json::to_vec(&settings).unwrap(),
            )))),
            created_at: 0,
            links: Deferred::default(),
        }
    }

    async fn read_link(
        db: &leas_db::Database,
        protocol_id: i64,
        endpoint_id: i64,
    ) -> Option<ProfileStats> {
        let mut conn = db.connection().await.unwrap();
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(protocol_id),
            leas_db::models::EndpointId::new(endpoint_id),
        )
        .first()
        .exec(&mut conn)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn connect_failure_placeholder_errors_without_touching_markers() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        // Endpoint row with one link (protocol id 100); its protocol config
        // is a placeholder so `ConfigBuilder::build` errors on either core.
        let mut row = fake_row(100, "h100.example", 1);
        let pid = row.links[0].protocol_id;
        row.protocols.insert(pid, placeholder_protocol(pid.get()));
        // Pre-existing latency + error markers must survive a connect
        // failure (a failed connect is NOT a ping — no markers written).
        let link = &mut row.links[0];
        link.latency = Some(Latency::Fast { delay: 42 });
        link.error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "previous failure".to_string(),
        });
        let traffic_before = link.traffic;
        // Persist rows: the connect task's `load_protocol_with_config` reads
        // the Protocol row (with config) from the DB.
        db.upsert_endpoint(&row.endpoint).await.unwrap();
        db.upsert_protocol(row.protocols.get(&pid).unwrap())
            .await
            .unwrap();
        db.upsert_link(&row.links[0]).await.unwrap();

        // AppState over the SAME database the rows were persisted to (the
        // connect task reads the Protocol row back from `state.db`).
        let mut state = crate::AppState::new(db, AppConfig::default()).await;
        state.endpoints = vec![row];
        state.filter_cache_valid.set(false);
        state.selected_index = 0;
        state.connect_to_profile(100);

        // Connect initiation bookkeeping: `connecting` in flight, the
        // connected endpoint registered, and last_used/last_seen patched
        // in-memory (mirrors the persisted write).
        assert!(state.connecting, "connecting flag set during connect");
        assert_eq!(state.connected_protocol_id, Some(100));
        let link = &state.endpoints[0].links[0];
        let used_at = link
            .last_used_at
            .expect("in-memory last_used_at set at initiation");
        assert_eq!(
            link.last_seen_at, used_at,
            "last_used mirrors last_seen (old semantics)"
        );

        // Drain until the connect task's error event lands (config build
        // fails on the placeholder before any binary lookup or core start).
        for _ in 0..200 {
            let _ = state.poll_core_events().await;
            if state.connection_error.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let err = state
            .connection_error
            .clone()
            .expect("connect failure surfaced as an event");
        assert!(err.contains("Config build failed"), "got: {err}");
        assert!(!state.connecting, "connecting cleared by the error event");
        assert_eq!(state.connected_core, None);
        assert_eq!(state.connected_protocol_id, None);

        // Failure surfaced as an event ONLY: latency/error markers and the
        // traffic counters are untouched.
        let link = &state.endpoints[0].links[0];
        assert!(
            link.latency.is_some(),
            "pre-existing latency marker preserved"
        );
        assert!(link.error.is_some(), "pre-existing error marker preserved");
        assert_eq!(
            link.traffic, traffic_before,
            "connect failure writes no traffic"
        );

        // Persisted consistency: the spawned update_last_used write lands
        // with the same timestamp the in-memory patch used.
        let mut stored = None;
        for _ in 0..100 {
            stored = read_link(&state.db, pid.get(), 100).await;
            if stored.as_ref().is_some_and(|l| l.last_used_at.is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stored = stored.expect("link persisted");
        let stored_used = stored.last_used_at.expect("last_used_at persisted");
        assert_eq!(
            stored.last_seen_at, stored_used,
            "DB write sets both columns"
        );
        assert_eq!(
            state.endpoints[0].links[0].last_used_at,
            Some(stored_used),
            "in-memory and persisted timestamps agree"
        );
    }

    #[tokio::test]
    async fn disconnect_flushes_pending_stats_and_clears_session_state() {
        let mut state =
            crate::ops::profiles::test_support::test_state(vec![fake_row(100, "h100.example", 1)])
                .await;
        // Isolate from the startup channels (whitelist load, auto-update):
        // replace the rx so only this test can feed events — deterministic.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.connected_core = Some(CoreType::Xray);
        state.connected_protocol_id = Some(100);
        state.current_traffic_up = 42;
        state.current_traffic_down = 84;
        state.connection_error = Some("stale error".to_string());

        // A poller tick in flight when disconnect is pressed: the delta must
        // be flushed into the link (in-memory + persisted), not lost with
        // the task abort. fake_row's link protocol id is id*100 = 10_000.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 10_000,
            today_up: 10,
            today_down: 20,
            total_up: 10,
            total_down: 20,
        })
        .await
        .unwrap();

        state.disconnect();

        // Pollers stopped: the stop signal was consumed. No session task was
        // registered in this test, so there is nothing left to wait on.
        assert!(state.disconnect_tx.is_none(), "stop signal consumed");
        assert!(
            state.core_task_handle.is_none(),
            "no session task to tear down"
        );
        // Session state cleared.
        assert_eq!(state.connected_core, None);
        assert_eq!(state.connected_protocol_id, None);
        assert!(!state.connecting);
        assert_eq!(state.connection_error, None, "stale error cleared");
        assert_eq!(state.current_traffic_up, 0, "actions-log traffic reset");
        assert_eq!(state.current_traffic_down, 0);
        // The in-flight delta was flushed into the link in-memory.
        let link = &state.endpoints[0].links[0];
        assert_eq!(link.traffic.today_up, 10);
        assert_eq!(link.traffic.today_down, 20);
        assert_eq!(link.traffic.total_up, 10);
        assert_eq!(link.traffic.total_down, 20);
        // ... and persisted by the spawned flush.
        let mut stored = None;
        for _ in 0..100 {
            stored = read_link(&state.db, 10_000, 100).await;
            if stored.as_ref().is_some_and(|l| l.traffic.total_up >= 10) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stored = stored.expect("link persisted");
        assert_eq!(stored.traffic.total_up, 10);
        assert_eq!(stored.traffic.total_down, 20);
        // Disconnect left no stragglers: draining the channel post-disconnect
        // finds nothing (the flush consumed the pending tick).
        assert!(!state.poll_core_events().await);
    }

    /// `disconnect` fires the stop signal and then lets the session task run
    /// its own teardown (for the native core, `server.shutdown()` and the
    /// closing `Disconnected` live there) — never an immediate abort, and never
    /// a blocked UI thread. The bounded waiter it leaves behind is what the
    /// next connect serializes on.
    #[tokio::test]
    async fn disconnect_lets_the_session_task_run_its_own_teardown() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut state =
            crate::ops::profiles::test_support::test_state(vec![fake_row(100, "h100.example", 1)])
                .await;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        // `release` stands in for a teardown that takes a while: the task
        // cannot finish until this test allows it, so "did the tail run?" is
        // decided by ordering instead of by a sleep.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let torn_down = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&torn_down);
        state.disconnect_tx = Some(stop_tx);
        state.core_task_handle = Some(tokio::spawn(async move {
            stop_rx.await.expect("stop signal delivered by disconnect");
            let _ = release_rx.await;
            flag.store(true, Ordering::SeqCst);
        }));

        state.disconnect();

        assert!(
            !torn_down.load(Ordering::SeqCst),
            "disconnect returns before the teardown finishes (the UI thread never blocks)"
        );
        let waiter = state
            .core_task_handle
            .take()
            .expect("the bounded teardown waiter is kept for the next session");
        release_tx
            .send(())
            .expect("teardown still running, not aborted");
        waiter.await.expect("waiter joins cleanly");
        assert!(
            torn_down.load(Ordering::SeqCst),
            "the session task ran its own tail instead of being aborted"
        );
    }

    #[test]
    fn clash_traffic_lines_map_to_per_line_deltas() {
        // sing-box `/traffic` emits one JSON line per second carrying that
        // second's delta. Two lines must produce two delta events (100, 50) —
        // never the running session total (100, 150) — or the stats handler's
        // accumulation would double-count on every event.
        let lines = [
            br#"{"up":100,"down":200}"#.as_slice(),
            br#"{"up":50,"down":75}"#.as_slice(),
        ];
        let events: Vec<CoreEvent> = lines
            .iter()
            .filter_map(|line| serde_json::from_slice::<ClashTraffic>(line).ok())
            .map(|t| clash_stats_event(7, &t))
            .collect();
        assert_eq!(events.len(), 2, "both lines parsed");
        let fields: Vec<(i64, i64, i64, i64, i64)> = events
            .iter()
            .map(|e| match e {
                CoreEvent::StatsUpdate {
                    protocol_id,
                    today_up,
                    today_down,
                    total_up,
                    total_down,
                } => (*protocol_id, *today_up, *today_down, *total_up, *total_down),
                other => panic!("expected StatsUpdate, got {other:?}"),
            })
            .collect();
        assert_eq!(
            fields,
            vec![(7, 100, 200, 100, 200), (7, 50, 75, 50, 75)],
            "each event carries only that line's delta"
        );
    }

    // ── Runtime core resolution (connect-time native selection) ───────────

    /// A VLESS row over the given transport. `Tcp` passes the capability gate;
    /// `Quic` is the capability-deferred case (native has no bare-QUIC arm).
    fn vless_config(transport: TransportConfig) -> ProtocolConfig {
        ProtocolConfig::Vless(leas_proto::proto_spec::VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        })
    }

    /// One (`link_core`, kind, forced, transport, `proxy_all_blocked`) → expected
    /// resolution table: the ten connect-time native-selection tests, each
    /// assertion kept as a named row. `transport: None` is the unloaded-config
    /// case; a `Some` transport builds the VLESS config the gate inspects.
    #[rstest]
    #[case::xray_stamped_native_kind_selects_the_in_process_core(
        CoreType::Xray, ProtocolKind::Vless, None, Some(TransportConfig::Tcp), false,
        (CoreType::Native, None)
    )]
    #[case::routing_rules_demote_native_to_the_link_core(
        CoreType::Xray, ProtocolKind::Vless, None, Some(TransportConfig::Tcp), true,
        (CoreType::Xray, Some(REFUSED_PROXY_ALL))
    )]
    #[case::capability_deferred_config_demotes_native(
        CoreType::Xray, ProtocolKind::Vless, None, Some(TransportConfig::Quic), false,
        (CoreType::Xray, Some(REFUSED_CAPABILITY))
    )]
    #[case::unloaded_config_never_reaches_native(
        CoreType::Xray, ProtocolKind::Vless, None, None, false,
        (CoreType::Xray, Some(REFUSED_UNLOADED))
    )]
    #[case::forced_native_passes_the_capability_gate(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::Native), Some(TransportConfig::Tcp), false,
        (CoreType::Native, None)
    )]
    #[case::forced_native_deferred_config_is_refused(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::Native), Some(TransportConfig::Quic), false,
        (CoreType::Xray, Some(REFUSED_CAPABILITY))
    )]
    #[case::forced_auto_passes_the_capability_gate(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::Auto), Some(TransportConfig::Tcp), false,
        (CoreType::Native, None)
    )]
    #[case::forced_auto_deferred_config_is_refused(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::Auto), Some(TransportConfig::Quic), false,
        (CoreType::Xray, Some(REFUSED_CAPABILITY))
    )]
    // SSR, not Shadowsocks: the plain-SS kind is native now, and SSR is its
    // closest relative that still has no native implementation, so the kind
    // gate — not the config gate — is what fires here.
    #[case::forced_native_on_a_non_native_kind_reports_the_kind_gate(
        CoreType::Xray, ProtocolKind::ShadowsocksR, Some(CoreType::Native), None, false,
        (CoreType::Xray, Some(REFUSED_KIND))
    )]
    #[case::forced_native_on_a_native_kind_still_needs_a_loaded_config(
        CoreType::Xray, ProtocolKind::Shadowsocks, Some(CoreType::Native), None, false,
        (CoreType::Xray, Some(REFUSED_UNLOADED))
    )]
    #[case::forced_legacy_xray_vetoes_native_and_keeps_the_stamp(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::Xray), Some(TransportConfig::Tcp), false,
        (CoreType::Xray, None)
    )]
    #[case::forced_legacy_singbox_vetoes_native_and_keeps_the_stamp(
        CoreType::Xray, ProtocolKind::Vless, Some(CoreType::SingBox), Some(TransportConfig::Tcp), false,
        (CoreType::Xray, None)
    )]
    #[case::singbox_stamped_link_never_runs_native(
        CoreType::SingBox, ProtocolKind::Vless, None, Some(TransportConfig::Tcp), false,
        (CoreType::SingBox, None)
    )]
    #[case::non_native_kind_keeps_the_link_core_silently(
        CoreType::Xray, ProtocolKind::Socks, None, None, false,
        (CoreType::Xray, None)
    )]
    fn resolve_runtime_core_over_inputs(
        #[case] link_core: CoreType,
        #[case] kind: ProtocolKind,
        #[case] forced: Option<CoreType>,
        #[case] transport: Option<TransportConfig>,
        #[case] proxy_all_blocked: bool,
        #[case] expected: (CoreType, Option<&'static str>),
    ) {
        let config = transport.map(vless_config);
        let got = resolve_runtime_core(link_core, kind, forced, config.as_ref(), proxy_all_blocked);
        assert_eq!(got, expected, "link_core {link_core:?}, kind {kind:?}");
    }
}
