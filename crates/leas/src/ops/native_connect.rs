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
use leas_db::models::{Endpoint, Protocol};
use leas_native::inbound::outbound::ProxyOutbound;
use leas_native::server::{NativeCoreServer, ServerConfig};
use leas_native::telemetry::{NativeEvent, Telemetry};
use leas_proto::proto_spec::{EndpointEssentials, HostKind};

use crate::try_send_or_warn;
use crate::types::CoreEvent;

/// Stats poll cadence (same as the xray gRPC poller).
const STATS_INTERVAL_SECS: u64 = 3;
/// Per-host snapshot cadence for the Sniffer pane (spec D10).
const SNIFFER_INTERVAL_SECS: u64 = 1;
/// Sys stats every Nth tick (~9 s, same as the xray poller).
const SYS_EVERY_TICKS: u8 = 3;
/// Telemetry channel depth (memory-diet Task 2): 16 events per queue — drops
/// are counted, never blocking, so depth is backpressure policy, not safety.
const TELEMETRY_CAP: usize = 16;

/// Run the native server for one connected profile; returns after the stop
/// signal (or a fatal error), having emitted `Disconnected`.
#[allow(clippy::too_many_arguments)]
pub async fn run_native_session(
    listen: &str,
    listen_port: u16,
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

    // The native session always speaks mixed (SOCKS5 + HTTP CONNECT on one
    // port), on the same effective port the inbound settings expose.
    let listen_addr: SocketAddr = match format!("{listen}:{listen_port}").parse() {
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

    let proxy = ProxyOutbound {
        protocol: config,
        kind: protocol.proto_kind,
        server: endpoint_essentials(endpoint, addresses),
        resolved_ip: None,
    };
    let (telemetry, mut events_rx) = Telemetry::new(TELEMETRY_CAP);
    let server =
        match NativeCoreServer::start(ServerConfig::new(listen_addr, proxy, telemetry.clone()))
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
        format!("listening mixed={}", server.listen_addr()),
    );
    try_send_or_warn(tx, CoreEvent::Connected, "connected");

    // Telemetry adapter: 3 s traffic deltas + ~9 s sys stats + live log and
    // trace forwarding, all on the shared `CoreEvent` shapes.
    let session_start = std::time::Instant::now();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(STATS_INTERVAL_SECS));
    ticker.tick().await;
    let mut sniffer_ticker =
        tokio::time::interval(std::time::Duration::from_secs(SNIFFER_INTERVAL_SECS));
    sniffer_ticker.tick().await;
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
            _ = sniffer_ticker.tick() => {
                try_send_or_warn(
                    tx,
                    CoreEvent::SnifferSample(Box::new(telemetry.snapshot())),
                    "sniffer_sample",
                );
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
/// consumes (mirrors `leas_db::models::endpoint_essentials` —
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
/// the statistics screen's system section and the Logs tab's `d` dump.
#[cfg(target_os = "linux")]
pub(crate) fn proc_rss_bytes() -> u64 {
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

/// The same figure on Windows: `WorkingSetSize` from
/// `K32GetProcessMemoryInfo` — the kernel's resident set, the number Task
/// Manager's "Memory" column shows.
#[cfg(windows)]
pub(crate) fn proc_rss_bytes() -> u64 {
    /// `PROCESS_MEMORY_COUNTERS` (`psapi.h`); only `cb` and
    /// `WorkingSetSize` are read, but the size must be exact.
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    // Both live in kernel32, which the Windows target links by default.
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut core::ffi::c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: u32::try_from(std::mem::size_of::<ProcessMemoryCounters>()).unwrap_or(0),
        ..ProcessMemoryCounters::default()
    };
    // SAFETY: `K32GetProcessMemoryInfo` writes at most `cb` bytes into the
    // struct we pass, and `cb` is that struct's own size. The current-process
    // pseudo-handle needs no close.
    let ok =
        unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, counters.cb) };
    if ok == 0 {
        0
    } else {
        u64::try_from(counters.working_set_size).unwrap_or(u64::MAX)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) const fn proc_rss_bytes() -> u64 {
    0
}
