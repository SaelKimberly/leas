//! gRPC client for the `StatsService` API shared by xray-core and sing-box.
//!
//! Both backends expose a `v2ray.core.app.stats.command.StatsService` gRPC API on
//! `127.0.0.1:62789`. This module provides a unified [`StatsProvider`] trait with
//! backend-specific implementations and a factory function.

use async_trait::async_trait;

pub(crate) mod proto_gen {
    tonic::include_proto!("v2ray.core.app.stats.command");
}

use proto_gen as proto;

/// Shared gRPC API endpoint on localhost.
pub const API_ENDPOINT: &str = "http://127.0.0.1:62789";

/// Timeout for establishing the gRPC channel (TCP + HTTP/2 handshake).
const GRPC_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Per-call deadline for gRPC stats requests.
const GRPC_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("gRPC status error: {0}")]
    Status(#[from] tonic::Status),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("gRPC call timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("gRPC error: {0}")]
    Other(String),
}

// ── System stats struct ─────────────────────────────────────────────

/// System statistics from the core process.
#[derive(Debug, Clone, Default)]
pub struct SysStats {
    pub num_goroutine: u32,
    pub alloc: u64,       // bytes allocated
    pub total_alloc: u64, // cumulative bytes allocated
    pub sys: u64,         // bytes obtained from OS
    pub uptime: u32,      // seconds since core start
}

// ── StatsProvider trait ─────────────────────────────────────────────

/// Unified interface for querying traffic and system stats from either
/// xray-core or sing-box via their shared `V2Ray` Stats gRPC API.
#[async_trait]
pub trait StatsProvider: Send + Sync {
    /// Query traffic stats matching the given pattern.
    ///
    /// With `reset=true` the counters are reset after query so each poll
    /// returns delta since the last query.
    async fn query_stats(&self, pattern: &str, reset: bool) -> Result<Vec<proto::Stat>, GrpcError>;
    /// Get system stats (memory, goroutines, uptime).
    async fn get_sys_stats(&self) -> Result<SysStats, GrpcError>;
    /// Return the gRPC API endpoint URL.
    fn api_endpoint(&self) -> &str;
}

// ── GrpcStatsClient ────────────────────────────────────────────────

/// gRPC client for xray-core and sing-box's shared `StatsService`.
/// Both backends expose the same V2Ray Stats API on the same endpoint.
pub struct GrpcStatsClient {
    channel: tonic::transport::Channel,
}

impl GrpcStatsClient {
    pub async fn connect() -> Result<Self, GrpcError> {
        Self::connect_timeout(API_ENDPOINT, GRPC_CONNECT_TIMEOUT).await
    }

    /// Connect to an arbitrary gRPC endpoint with an explicit connect timeout.
    async fn connect_timeout(
        endpoint: &str,
        connect_timeout: std::time::Duration,
    ) -> Result<Self, GrpcError> {
        let uri = endpoint
            .parse::<tonic::transport::Uri>()
            .map_err(|e| GrpcError::Other(e.to_string()))?;
        let channel = tonic::transport::Endpoint::from(uri)
            .connect_timeout(connect_timeout)
            .timeout(GRPC_CALL_TIMEOUT)
            .connect()
            .await?;
        Ok(Self { channel })
    }
}

#[async_trait]
impl StatsProvider for GrpcStatsClient {
    async fn query_stats(&self, pattern: &str, reset: bool) -> Result<Vec<proto::Stat>, GrpcError> {
        let mut client = proto::stats_service_client::StatsServiceClient::new(self.channel.clone());
        let response = tokio::time::timeout(
            GRPC_CALL_TIMEOUT,
            client.query_stats(tonic::Request::new(proto::QueryStatsRequest {
                pattern: pattern.to_string(),
                reset,
                patterns: vec![],
                regexp: false,
            })),
        )
        .await
        .map_err(|_| GrpcError::Timeout(GRPC_CALL_TIMEOUT))??;
        Ok(response.into_inner().stat)
    }

    async fn get_sys_stats(&self) -> Result<SysStats, GrpcError> {
        let mut client = proto::stats_service_client::StatsServiceClient::new(self.channel.clone());
        let response = tokio::time::timeout(
            GRPC_CALL_TIMEOUT,
            client.get_sys_stats(tonic::Request::new(proto::SysStatsRequest {})),
        )
        .await
        .map_err(|_| GrpcError::Timeout(GRPC_CALL_TIMEOUT))??;
        let s = response.into_inner();
        Ok(SysStats {
            num_goroutine: s.num_goroutine,
            alloc: s.alloc,
            total_alloc: s.total_alloc,
            sys: s.sys,
            uptime: s.uptime,
        })
    }

    fn api_endpoint(&self) -> &str {
        API_ENDPOINT
    }
}

// ── Factory ─────────────────────────────────────────────────────────

/// Create a [`StatsProvider`] for the shared V2Ray Stats API.
pub async fn create_stats_provider() -> Result<Box<dyn StatsProvider>, GrpcError> {
    Ok(Box::new(GrpcStatsClient::connect().await?))
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format bytes to human-readable string (B/KB/MB/GB/TB/PB).
#[must_use]
pub fn format_bytes(bytes: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut b = bytes as f64;
    for unit in UNITS {
        if b < 1024.0 {
            return format!("{b:.1} {unit}");
        }
        b /= 1024.0;
    }
    format!("{b:.1} PB")
}

/// Format uptime seconds to human-readable string.
#[must_use]
pub fn format_uptime(secs: u32) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    match (hours, minutes, seconds) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, 0, 0) => format!("{h}h"),
        (h, m, s) => format!("{h}h {m}m {s}s"),
    }
}

/// Mock StatsProvider for testing — returns pre-configured stats without a real gRPC connection.
#[derive(Debug, Clone)]
pub struct MockStatsProvider {
    pub stats: Vec<(String, i64)>,
    pub sys: SysStats,
    pub query_error: Option<String>,
}

impl MockStatsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: Vec::new(),
            sys: SysStats::default(),
            query_error: None,
        }
    }
}

impl Default for MockStatsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StatsProvider for MockStatsProvider {
    async fn query_stats(
        &self,
        _pattern: &str,
        _reset: bool,
    ) -> Result<Vec<proto::Stat>, GrpcError> {
        if let Some(msg) = &self.query_error {
            return Err(GrpcError::InvalidResponse(msg.clone()));
        }
        Ok(self
            .stats
            .iter()
            .map(|(n, v)| proto::Stat {
                name: n.clone(),
                value: *v,
            })
            .collect())
    }

    async fn get_sys_stats(&self) -> Result<SysStats, GrpcError> {
        if let Some(msg) = &self.query_error {
            return Err(GrpcError::InvalidResponse(msg.clone()));
        }
        Ok(self.sys.clone())
    }

    fn api_endpoint(&self) -> &str {
        "http://127.0.0.1:62789"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStatsProvider {
        stats: Vec<(String, i64)>,
        sys: SysStats,
        err: Option<String>,
    }

    #[async_trait]
    impl StatsProvider for TestStatsProvider {
        async fn query_stats(
            &self,
            _pattern: &str,
            _reset: bool,
        ) -> Result<Vec<proto::Stat>, GrpcError> {
            if let Some(msg) = &self.err {
                return Err(GrpcError::InvalidResponse(msg.clone()));
            }
            Ok(self
                .stats
                .iter()
                .map(|(n, v)| proto::Stat {
                    name: n.clone(),
                    value: *v,
                })
                .collect())
        }

        async fn get_sys_stats(&self) -> Result<SysStats, GrpcError> {
            if let Some(msg) = &self.err {
                return Err(GrpcError::InvalidResponse(msg.clone()));
            }
            Ok(self.sys.clone())
        }

        fn api_endpoint(&self) -> &str {
            "http://127.0.0.1:62789"
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.0 B");
        assert_eq!(format_bytes(500), "500.0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(120), "2m 0s");
        assert_eq!(format_uptime(3600), "1h");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
    }

    #[tokio::test]
    async fn connect_to_unreachable_port_times_out_fast() {
        let t = std::time::Instant::now();
        let result = GrpcStatsClient::connect_timeout(
            "http://127.0.0.1:1", // nothing listens here
            std::time::Duration::from_millis(500),
        )
        .await;
        assert!(result.is_err());
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "must fail fast"
        );
    }

    #[tokio::test]
    async fn mock_stats_provider_works() {
        let provider = TestStatsProvider {
            stats: vec![("inbound>>>test>>>traffic>>>downlink".into(), 1024)],
            sys: SysStats::default(),
            err: None,
        };
        let result = provider.query_stats("inbound>>>", false).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "inbound>>>test>>>traffic>>>downlink");
        assert_eq!(result[0].value, 1024);
    }

    #[tokio::test]
    async fn mock_stats_provider_error() {
        let provider = TestStatsProvider {
            stats: vec![],
            sys: SysStats::default(),
            err: Some("not connected".into()),
        };
        let result = provider.query_stats("inbound>>>", false).await;
        assert!(result.is_err());
    }
}
