//! In-process native-core session for `connect_to_profile` (spec brief §3).
//!
//! Mirrors the subprocess arms of `connect.rs`: bind local listeners, signal
//! `Connected`, then run the telemetry adapter (traffic deltas, sys stats,
//! log forwarding, per-connection trace) until the stop signal, then shut
//! down and signal `Disconnected`. Deltas reuse the same `StatsUpdate`
//! shapes the xray gRPC poller emits, so persistence and screens behave
//! identically.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};

use leas_core::grpc_client::SysStats;
use leas_core::log_heed::LogMessage;
use leas_core::{BuildParams, CoreType};
use leas_db::models::{Endpoint, Protocol};
use leas_native::inbound::outbound::ProxyOutbound;
use leas_native::server::{NativeCoreServer, ServerConfig};
use leas_native::telemetry::{NativeEvent, Telemetry};
use leas_proto::proto_spec::{EndpointEssentials, HostKind};

use crate::try_send_or_warn;
use crate::types::CoreEvent;

/// Stats poll cadence (same as the xray gRPC poller).
const STATS_INTERVAL_SECS: u64 = 3;
/// Sys stats every Nth tick (~9 s, same as the xray poller).
const SYS_EVERY_TICKS: u8 = 3;
/// Telemetry channel depth (memory-diet Task 2): 16 events per queue — drops
/// are counted, never blocking, so depth is backpressure policy, not safety.
const TELEMETRY_CAP: usize = 16;

/// Run the native server for one connected profile; returns after the stop
/// signal (or a fatal error), having emitted `Disconnected`.
#[allow(clippy::too_many_arguments)]
pub async fn run_native_session(
    params: &BuildParams,
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    protocol: &Protocol,
    tx: &mpsc::Sender<CoreEvent>,
    log_sender: &Option<std::sync::mpsc::SyncSender<LogMessage>>,
    mut stop_rx: oneshot::Receiver<()>,
    protocol_id: i64,
) {
    if protocol.config.is_unloaded() {
        try_send_or_warn(
            tx,
            CoreEvent::Error("Protocol config not loaded for connection".to_string()),
            "native_config_unloaded",
        );
        return;
    }
    let config = protocol.config.get().0.clone();

    let socks_addr: SocketAddr = match format!("{}:{}", params.listen, params.socks_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            try_send_or_warn(
                tx,
                CoreEvent::Error(format!("Invalid native listen address: {e}")),
                "native_listen_invalid",
            );
            return;
        }
    };
    let http_addr: Option<SocketAddr> = match params.http_port {
        Some(port) => match format!("{}:{port}", params.listen).parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                try_send_or_warn(
                    tx,
                    CoreEvent::Error(format!("Invalid native HTTP listen address: {e}")),
                    "native_http_listen_invalid",
                );
                return;
            }
        },
        None => None,
    };

    let proxy = ProxyOutbound {
        protocol: config,
        kind: protocol.proto_kind,
        server: endpoint_essentials(endpoint, addresses),
        resolved_ip: None,
    };
    let (telemetry, mut events_rx) = Telemetry::new(TELEMETRY_CAP);
    let server = match NativeCoreServer::start(ServerConfig::new(
        socks_addr,
        http_addr,
        proxy,
        telemetry.clone(),
    ))
    .await
    {
        Ok(server) => server,
        Err(e) => {
            try_send_or_warn(
                tx,
                CoreEvent::Error(format!("Failed to start native core: {e}")),
                "native_start_error",
            );
            return;
        }
    };

    telemetry.log(
        "info",
        "leas_native::server",
        format!(
            "listening socks5={} http={http_addr:?}",
            server.socks_addr()
        ),
    );
    try_send_or_warn(tx, CoreEvent::Connected(CoreType::Native), "connected");

    // Telemetry adapter: 3 s traffic deltas + ~9 s sys stats + live log and
    // trace forwarding, all on the shared `CoreEvent` shapes.
    let session_start = std::time::Instant::now();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(STATS_INTERVAL_SECS));
    ticker.tick().await;
    let mut sys_tick_counter = 0u8;
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            event = events_rx.recv() => {
                match event {
                    Some(NativeEvent::Log { level, target, message }) => {
                        if let Some(sender) = log_sender {
                            let _ = sender.try_send(LogMessage {
                                level: level.to_string(),
                                target: target.to_string(),
                                message,
                                timestamp_nanos: now_nanos(),
                            });
                        }
                    }
                    Some(NativeEvent::Trace(trace)) => {
                        try_send_or_warn(tx, CoreEvent::NativeTrace(trace), "native_trace");
                    }
                    // Deltas are drained by the poller below.
                    Some(NativeEvent::Traffic { .. }) => {}
                    None => break,
                }
            }
            _ = ticker.tick() => {
                let (up, down) = telemetry.drain_traffic();
                try_send_or_warn(
                    tx,
                    CoreEvent::StatsUpdate {
                        protocol_id,
                        today_up: saturating_i64(up),
                        today_down: saturating_i64(down),
                        total_up: saturating_i64(up),
                        total_down: saturating_i64(down),
                    },
                    "native_stats_update",
                );
                sys_tick_counter += 1;
                if sys_tick_counter >= SYS_EVERY_TICKS {
                    sys_tick_counter = 0;
                    let rss = proc_rss_bytes();
                    try_send_or_warn(
                        tx,
                        CoreEvent::SysStatsUpdate(SysStats {
                            num_goroutine: 0,
                            alloc: rss,
                            total_alloc: rss,
                            sys: rss,
                            uptime: session_start.elapsed().as_secs().min(u64::from(u32::MAX)) as u32,
                        }),
                        "native_sys_stats_update",
                    );
                }
            }
        }
    }

    server.shutdown().await;
    try_send_or_warn(tx, CoreEvent::Disconnected, "disconnected");
}

/// Map a db `Endpoint` to the proto `EndpointEssentials` the proxy outbound
/// consumes (mirrors `leas_core::config_builder::endpoint_essentials` —
/// kept local because that helper is crate-private to leas-core).
#[must_use]
pub(crate) fn endpoint_essentials(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
) -> EndpointEssentials {
    let (host, host_type) = if endpoint.is_dns() {
        (endpoint.dns_name(), HostKind::Dns)
    } else {
        match addresses.first() {
            Some(std::net::IpAddr::V4(_)) => (addresses[0].to_string(), HostKind::Ipv4),
            Some(std::net::IpAddr::V6(_)) => (addresses[0].to_string(), HostKind::Ipv6),
            None => (String::new(), HostKind::Undefined),
        }
    };
    EndpointEssentials {
        host,
        host_type,
        port: endpoint.port,
        ports: endpoint.ports.clone(),
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Resident memory of this process (the native core runs in-process), for
/// the statistics screen's system section. Linux-only; zero elsewhere.
#[cfg(target_os = "linux")]
fn proc_rss_bytes() -> u64 {
    // `VmRSS:` is reported in kB by the kernel's own formatter, so this needs
    // no page-size assumption (the `statm` page count did, and 4096 is wrong
    // on any kernel with a larger base page).
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let kb = line.strip_prefix("VmRSS:")?;
                kb.split_whitespace().next()?.parse::<u64>().ok()
            })
        })
        .map_or(0, |kb| kb.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
fn proc_rss_bytes() -> u64 {
    0
}
