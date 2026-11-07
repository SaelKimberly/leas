//! Native-shared system statistics type and formatters.
//!
//! The gRPC Stats client (`StatsProvider`, `GrpcStatsClient`) moved to the
//! dev-only `leas-oracles` crate: the client is native-only, so `leas-core`
//! carries no tonic/prost edge. The native telemetry writes the same
//! [`SysStats`] shape.

/// System statistics from the core process.
#[derive(Debug, Clone, Default)]
pub struct SysStats {
    pub num_goroutine: u32,
    pub alloc: u64,       // bytes allocated
    pub total_alloc: u64, // cumulative bytes allocated
    pub sys: u64,         // bytes obtained from OS
    pub uptime: u32,      // seconds since core start
}

/// Format bytes to human-readable string (B/KB/MB/GB/TB/PB).
#[must_use]
// Display only: lossy above 2^53 bytes (8 PiB) is acceptable for a human-readable size.
#[allow(clippy::cast_precision_loss)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.0 B");
        assert_eq!(format_bytes(500), "500.0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(120), "2m 0s");
        assert_eq!(format_uptime(3600), "1h");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
    }
}
