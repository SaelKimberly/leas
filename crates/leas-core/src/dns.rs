use std::net::IpAddr;
use tokio::time::{Duration, timeout};

/// Resolve a hostname to IP addresses.
///
/// Uses `tokio::net::lookup_host` with a 5s timeout.
/// Returns IPv4 first, IPv6 second, deduplicated.
pub async fn resolve_dns_name(host: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let lookup = tokio::net::lookup_host((host, 443));
    match timeout(Duration::from_secs(5), lookup).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            // Dedup while preserving order
            ips.sort();
            ips.dedup();
            // Sort: IPv4 first, IPv6 second
            ips.sort_by_key(|ip| match ip {
                IpAddr::V4(_) => 0u8,
                IpAddr::V6(_) => 1,
            });
            Ok(ips)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("DNS resolution timed out for {host}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        let ips = resolve_dns_name("localhost").await.unwrap();
        assert!(!ips.is_empty(), "localhost should resolve");
        assert!(ips.contains(&IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn test_resolve_timeout_on_garbage() {
        let result = resolve_dns_name("thishostnamedoesnotexist-hopefully-123456789.com").await;
        // Should be an error (likely timeout or not found)
        assert!(result.is_err());
    }
}
